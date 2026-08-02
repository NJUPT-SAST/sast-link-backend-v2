package session

import (
	"bytes"
	"context"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
	_ "golang.org/x/image/webp"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// maxAvatarSize is the PUT /user/avatar upload ceiling from PRD §4.9 (5MB). The
// reader is capped at maxAvatarSize+1 so an oversized body is detected by length
// rather than by trusting the multipart part's declared size.
const maxAvatarSize = 5 << 20

// avatarMIME maps the three accepted image formats to their canonical content
// type, used both for the acceptance check and the COS upload header.
var avatarMIME = map[string]string{
	"image/jpeg": "image/jpeg",
	"image/png":  "image/png",
	"image/webp": "image/webp",
}

// avatarExtensions maps the accepted content types to object key suffixes.
var avatarExtensions = map[string]string{
	"image/jpeg": "jpg",
	"image/png":  "png",
	"image/webp": "webp",
}

// UploadAvatar stores the caller's avatar image in object storage, writes the
// public URL into profile.avatar, reviews the image when auditing is enabled
// and retires the previous avatar object.
//
// Ordering is deliberate: the new object is uploaded and reviewed before the
// database is touched, so a rejected image never leaves profile.avatar pointing
// at something that was not vetted; the profile write happens only after the
// review verdict. A database failure compensates by deleting the fresh object,
// so no orphan is left behind.
func (s Service) UploadAvatar(ctx context.Context, input UploadAvatarInput) (*UploadAvatarResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if s.AvatarStore == nil {
		return nil, newError(ErrObjectUploadFailed, "对象存储未配置", nil)
	}
	if err := s.checkEndpointLimit(ctx, s.AvatarLimiter, "upload_avatar", "user:"+strconv.FormatInt(input.UserID, 10)); err != nil {
		return nil, err
	}

	// Resolve the caller before spending anything on the body: a deleted or
	// unknown user must not make the service read (or store) their upload.
	user, err := s.Users.FindByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询用户资料失败", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "用户已注销", nil)
	}

	data, mime, err := readAvatar(input.Content, input.Size)
	if err != nil {
		return nil, err
	}

	contentType := avatarMIME[mime]
	key := "avatar/" + strconv.FormatInt(input.UserID, 10) + "/" + uuid.NewString() + "." + avatarExtensions[mime]
	avatarURL, err := s.AvatarStore.Upload(ctx, key, bytes.NewReader(data), contentType, int64(len(data)))
	if err != nil {
		return nil, newError(ErrObjectUploadFailed, "头像上传失败", err)
	}

	// The image was stored but not yet vetted. Any failure past this point must
	// remove it: a rejected review, a missing profile write, or an abandoned
	// request would otherwise leave an unvetted or orphaned object behind.
	cleanup := func(cause error) error {
		deleteCtx := context.WithoutCancel(ctx)
		if deleteErr := s.AvatarStore.Delete(deleteCtx, key); deleteErr != nil {
			slog.ErrorContext(ctx, "cleanup avatar object after failure", "key", key, "error", deleteErr)
		}
		return cause
	}

	if s.AvatarAuditor != nil {
		verdict, auditErr := s.AvatarAuditor.AuditImage(ctx, key)
		if auditErr != nil {
			// Fail-closed: an unreachable review must not let an unvetted image
			// through. The caller sees the upload failed and can retry.
			return nil, cleanup(newError(ErrObjectUploadFailed, "头像审核服务暂不可用，请稍后重试", auditErr))
		}
		if verdict.Sensitive {
			if err := s.audit(ctx, &input.UserID, "upload_avatar", "user", resourceID(input.UserID), false, errcode.CodeValidationFailed,
				input.ClientIP, "", map[string]any{"label": verdict.Label}); err != nil {
				slog.Error("audit avatar rejection", "user_id", input.UserID, "error", err)
			}
			return nil, cleanup(newError(ErrValidationFailed, "头像未通过内容审核", nil))
		}
	}

	// Snapshot the previous avatar value before the write: the repository may
	// reload or mutate the aggregate, and the cleanup must compare against what
	// was stored before this call.
	var previousAvatar *string
	if user.Profile != nil {
		previousAvatar = user.Profile.Avatar
	}
	if _, err := s.Users.UpdateProfile(ctx, input.UserID, repository.ProfileUpdate{Avatar: &avatarURL}); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, cleanup(newError(ErrInvalidToken, "身份主体无效", err))
		}
		return nil, cleanup(newError(ErrDatabase, "更新头像失败", err))
	}

	// Retire the superseded object best-effort: a leftover is a storage leak,
	// not a correctness problem, so a failed delete logs and moves on.
	if previousAvatar != nil && *previousAvatar != avatarURL {
		if oldKey := avatarKeyFromURL(*previousAvatar, avatarURL, key); oldKey != "" {
			if deleteErr := s.AvatarStore.Delete(context.WithoutCancel(ctx), oldKey); deleteErr != nil {
				slog.WarnContext(ctx, "delete superseded avatar object", "key", oldKey, "error", deleteErr)
			}
		}
	}

	if auditErr := s.audit(ctx, &input.UserID, "upload_avatar", "user", resourceID(input.UserID), true, 0,
		input.ClientIP, "", map[string]any{"avatar_url": avatarURL}); auditErr != nil {
		slog.Error("audit avatar upload", "user_id", input.UserID, "error", auditErr)
	}
	return &UploadAvatarResult{AvatarURL: avatarURL}, nil
}

// readAvatar validates the uploaded bytes against the PRD §4.9 rules: at most
// 5MB, decodable jpg/png/webp. It returns the raw bytes and the detected MIME
// type. The declared size only enables an early rejection; the actual read is
// what the limit is enforced on, so a lying part header cannot smuggle a larger
// body into storage.
func readAvatar(content io.Reader, declaredSize int64) ([]byte, string, error) {
	if declaredSize > maxAvatarSize {
		return nil, "", newError(ErrInvalidInput, "头像大小不能超过 5MB", nil)
	}
	data, err := io.ReadAll(io.LimitReader(content, maxAvatarSize+1))
	if err != nil {
		return nil, "", newError(ErrInvalidInput, "读取头像内容失败", err)
	}
	if len(data) > maxAvatarSize {
		return nil, "", newError(ErrInvalidInput, "头像大小不能超过 5MB", nil)
	}
	if len(data) == 0 {
		return nil, "", newError(ErrInvalidInput, "头像内容为空", nil)
	}
	// Detect by magic bytes, never by the multipart filename or content type:
	// both are client-supplied and would let an HTML file masquerade as an image.
	detected := mimetype.Detect(data[:min(len(data), 512)])
	if _, ok := avatarMIME[detected.String()]; !ok {
		return nil, "", newError(ErrInvalidInput, "头像格式仅支持 jpg/png/webp", nil)
	}
	// Confirm the file actually decodes as the image it claims to be. webp is
	// registered into the stdlib image package by golang.org/x/image/webp, so one
	// DecodeConfig call covers all three accepted formats.
	if _, _, err := image.DecodeConfig(bytes.NewReader(data)); err != nil {
		return nil, "", newError(ErrInvalidInput, "头像文件已损坏或不是有效图片", nil)
	}
	return data, detected.String(), nil
}

// avatarKeyFromURL extracts the object key of a previously stored avatar URL.
// The new URL is {base}/{key}, so any previous URL under the same base yields
// its key by trimming the base prefix. The result is validated before use:
// avatar keys are always "avatar/...", and a key outside that shape means the
// old URL does not belong to this service's storage (e.g. a migrated external
// URL), which must be left alone rather than deleted by guesswork.
func avatarKeyFromURL(previousURL, newURL, newKey string) string {
	if !strings.HasPrefix(previousURL, newURL[:len(newURL)-len(newKey)]) {
		return ""
	}
	key := strings.TrimPrefix(previousURL, newURL[:len(newURL)-len(newKey)])
	if key == "" || key == newKey || strings.Contains(key, "..") || !strings.HasPrefix(key, "avatar/") {
		return ""
	}
	return key
}

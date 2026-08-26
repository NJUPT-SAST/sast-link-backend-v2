package session

import (
	"bytes"
	"context"
	"errors"
	"image"
	_ "image/jpeg"
	"image/png"
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

// maxAvatarSize is the PUT /user/avatar upload ceiling (1MB); the reader is
// capped at maxAvatarSize+1 so an oversized body is detected by length rather
// than by the multipart part's declared size.
const maxAvatarSize = 1 << 20

// maxAvatarDimension bounds the decoded width and height. It is checked from the
// image header (DecodeConfig) so a pathological image never reaches the content
// review or client rendering.
const maxAvatarDimension = 4096

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
// database is touched, so profile.avatar never points at an unvetted image; a
// database failure deletes the fresh object so no orphan is left behind.
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
	// unknown user must not make the service read or store their upload.
	// FindProfileByID also brings the current profile row, whose avatar is the
	// object this upload supersedes.
	user, err := s.Users.FindProfileByID(ctx, input.UserID)
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
		// The multipart filename is client-supplied, so it only ever reaches a
		// log line — never storage or a URL — and only on the rejection path.
		slog.WarnContext(ctx, "reject avatar upload", "filename", input.Filename, "error", err)
		return nil, err
	}

	contentType := avatarMIME[mime]
	key := "avatar/" + strconv.FormatInt(input.UserID, 10) + "/" + uuid.NewString() + "." + avatarExtensions[mime]
	avatarURL, err := s.AvatarStore.Upload(ctx, key, bytes.NewReader(data), contentType, int64(len(data)))
	if err != nil {
		return nil, newError(ErrObjectUploadFailed, "头像上传失败", err)
	}

	// The image was stored but not yet vetted; any failure past this point must
	// remove it, so a rejected review or a missing profile write leaves no
	// unvetted or orphaned object behind.
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
			// Fail-closed: an unreachable review must not let an unvetted image through;
			// 50300 tells the caller to retry.
			return nil, cleanup(newError(ErrDependencyUnavailable, "头像审核服务暂不可用，请稍后重试", auditErr))
		}
		if verdict.Sensitive {
			if err := s.audit(ctx, &input.UserID, "upload_avatar", "user", resourceID(input.UserID), nullableString(s.actorClientID(input.ActorClientID)), false, errcode.CodeAvatarRejected,
				input.ClientIP, input.UserAgent, map[string]any{"label": verdict.Label}); err != nil {
				slog.Error("audit avatar rejection", "user_id", input.UserID, "error", err)
			}
			return nil, cleanup(newError(ErrAvatarRejected, "头像未通过内容审核", nil))
		}
	}

	// Snapshot the previous avatar value before the write, so cleanup compares
	// against what was stored before this call.
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

	// Retire the superseded object best-effort: a failed delete logs and moves on,
	// because a leftover is a storage leak, not a correctness problem. The
	// previous value is the pre-write snapshot, so two concurrent uploads each
	// retire only what they saw before their own write.
	if previousAvatar != nil && *previousAvatar != avatarURL {
		if oldKey := avatarKeyFromURL(*previousAvatar, avatarURL, key); oldKey != "" {
			if deleteErr := s.AvatarStore.Delete(context.WithoutCancel(ctx), oldKey); deleteErr != nil {
				slog.WarnContext(ctx, "delete superseded avatar object", "key", oldKey, "error", deleteErr)
			}
		}
	}

	if auditErr := s.audit(ctx, &input.UserID, "upload_avatar", "user", resourceID(input.UserID), nullableString(s.actorClientID(input.ActorClientID)), true, 0,
		input.ClientIP, input.UserAgent, map[string]any{"avatar_url": avatarURL}); auditErr != nil {
		slog.Error("audit avatar upload", "user_id", input.UserID, "error", auditErr)
	}
	return &UploadAvatarResult{AvatarURL: avatarURL}, nil
}

// readAvatar validates the uploaded bytes: at most 1MB, decodable
// jpg/png/webp within maxAvatarDimension, returning the raw bytes and the
// detected MIME type. The declared size only enables an early rejection; the
// actual read enforces the limit, so a lying part header cannot smuggle a
// larger body into storage.
func readAvatar(content io.Reader, declaredSize int64) ([]byte, string, error) {
	if declaredSize > maxAvatarSize {
		return nil, "", newError(ErrInvalidInput, "头像大小不能超过 1MB", nil)
	}
	data, err := io.ReadAll(io.LimitReader(content, maxAvatarSize+1))
	if err != nil {
		return nil, "", newError(ErrInvalidInput, "读取头像内容失败", err)
	}
	if len(data) > maxAvatarSize {
		return nil, "", newError(ErrInvalidInput, "头像大小不能超过 1MB", nil)
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
	//
	// DecodeConfig reads only the header, not the pixel data: a full Decode of a
	// 1MB image can expand to hundreds of megabytes of pixels, which any
	// logged-in user could weaponize as a memory bomb. The width and height are
	// checked against maxAvatarDimension for the same reason, so a pathological
	// pixel count never reaches the content review or client rendering.
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, "", newError(ErrInvalidInput, "头像文件已损坏或不是有效图片", nil)
	}
	if cfg.Width > maxAvatarDimension || cfg.Height > maxAvatarDimension {
		return nil, "", newError(ErrInvalidInput, "头像分辨率不能超过 4096×4096", nil)
	}
	// Re-encode from the decoded pixels so only the real image content survives:
	// a polyglot trailer (a magic-valid image followed by HTML/JS) is dropped
	// before the bytes reach storage. The dimension cap bounds the expanded
	// pixel buffer this costs (4096²×4 = 64MB worst case). Every accepted input
	// is normalized to PNG, so the stored bytes are independent of the claimed
	// source format.
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", newError(ErrInvalidInput, "头像文件已损坏或不是有效图片", nil)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, "", newError(ErrInternal, "头像重新编码失败", err)
	}
	return buf.Bytes(), "image/png", nil
}

// avatarKeyFromURL extracts the object key of a previously stored avatar URL:
// the new URL is {base}/{key}, so a previous URL under the same base yields its
// key by trimming the base prefix. Keys outside the "avatar/..." shape mean the
// old URL is not this service's storage (e.g. a migrated external URL) and must
// be left alone rather than deleted by guesswork.
func avatarKeyFromURL(previousURL, newURL, newKey string) string {
	// The new URL is expected to end with the fresh key; guard the slice below
	// against an Upload implementation that returns something else.
	if !strings.HasSuffix(newURL, newKey) {
		return ""
	}
	if !strings.HasPrefix(previousURL, newURL[:len(newURL)-len(newKey)]) {
		return ""
	}
	key := strings.TrimPrefix(previousURL, newURL[:len(newURL)-len(newKey)])
	if key == "" || key == newKey || strings.Contains(key, "..") || !strings.HasPrefix(key, "avatar/") {
		return ""
	}
	return key
}

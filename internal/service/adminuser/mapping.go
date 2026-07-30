package adminuser

import (
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func userListItem(row repository.AdminUserRow) UserListItem {
	item := UserListItem{
		ID:          row.ID,
		Name:        row.Name,
		StudentID:   row.StudentID,
		LoginEmail:  row.LoginEmail,
		Role:        string(row.Role),
		State:       string(row.State),
		EmailType:   string(row.EmailType),
		PhoneNumber: row.PhoneNumber,
		QQNumber:    row.QQNumber,
		College:     string(row.College),
		Major:       row.Major,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
	if row.Department != nil {
		department := string(*row.Department)
		item.Department = &department
	}
	return item
}

func userDetail(user *model.User) UserDetail {
	detail := UserDetail{
		ID:          user.ID,
		Name:        user.Name,
		LoginEmail:  user.LoginEmail,
		Role:        string(user.Role),
		State:       string(user.State),
		EmailType:   string(user.EmailType),
		PhoneNumber: user.PhoneNumber,
		QQNumber:    user.QQNumber,
		StudentID:   user.StudentID,
		College:     string(user.College),
		Major:       user.Major,
		Identities:  make([]IdentityDetail, 0, len(user.Identities)),
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}
	if user.Profile != nil {
		detail.Profile = &ProfileDetail{
			Nickname:  user.Profile.Nickname,
			Intro:     user.Profile.Intro,
			Email:     user.Profile.Email,
			Avatar:    user.Profile.Avatar,
			BlogURL:   user.Profile.BlogURL,
			GitHubURL: user.Profile.GitHubURL,
			CreatedAt: user.Profile.CreatedAt,
			UpdatedAt: user.Profile.UpdatedAt,
		}
		if user.Profile.Department != nil {
			department := string(*user.Profile.Department)
			detail.Profile.Department = &department
		}
	}
	for _, identity := range user.Identities {
		detail.Identities = append(detail.Identities, IdentityDetail{
			ID:             identity.ID,
			Provider:       string(identity.Provider),
			ProviderID:     identity.ProviderID,
			IdentityData:   identity.IdentityData,
			TokenExpiresAt: identity.TokenExpiresAt,
			CreatedAt:      identity.CreatedAt,
			UpdatedAt:      identity.UpdatedAt,
		})
	}
	return detail
}

func auditLogItem(entry model.AuditLog) AuditLogItem {
	item := AuditLogItem{
		ID:         entry.ID,
		UserID:     entry.UserID,
		Action:     entry.Action,
		Resource:   entry.Resource,
		ResourceID: entry.ResourceID,
		Detail:     entry.Detail,
		ClientIP:   entry.ClientIP,
		UserAgent:  entry.UserAgent,
		ErrCode:    entry.ErrCode,
		CreatedAt:  entry.CreatedAt,
	}
	// success is NOT NULL with a default in V001, so a null can only come from a row
	// written before that column existed. Reporting it as false would label a
	// historical success as a failure, and the column's default is true.
	item.Success = entry.Success == nil || *entry.Success
	return item
}

// normalizePaging clamps a requested page window. A non-positive page or size is
// the handler's signal that the caller omitted it; an out-of-range size is capped
// rather than rejected, matching the contract's documented maximum.
func normalizePaging(page, pageSize, defaultSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = defaultSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

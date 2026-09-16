package adminuser

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Stats returns the aggregate account counts for the console overview.
func (s Service) Stats(ctx context.Context) (repository.UserStats, error) {
	if s.Users == nil {
		// A missing dependency is a wiring fault, not an empty console: answering a
		// zeroed aggregate would report "no accounts" for a service that cannot read
		// any.
		return repository.UserStats{}, newError(ErrInternal, "用户仓储未配置", nil)
	}
	return s.Users.Stats(ctx)
}

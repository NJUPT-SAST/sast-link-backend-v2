package adminuser

import (
	"context"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// Stats returns the aggregate account counts for the console overview.
func (s Service) Stats(ctx context.Context) (repository.UserStats, error) {
	if s.Users == nil {
		return repository.UserStats{}, nil
	}
	return s.Users.Stats(ctx)
}

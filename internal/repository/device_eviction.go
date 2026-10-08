package repository

import (
	"context"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// ResolveDeviceEviction verifies the exact issuance which caused an eviction.
// Failed refresh rotations never persist this refresh-token hash and cannot revoke a different
// device. Owner checks on BOTH families prevent a corrupt journal from crossing
// principals. The revoke and blacklist outbox commit together; ack happens later.
func (r *TokenRepository) ResolveDeviceEviction(ctx context.Context, userID int64, tokenHash, sourceFamily, evicted string, sourceExpiry, now time.Time) (bool, error) {
	if userID <= 0 || tokenHash == "" || sourceFamily == "" || evicted == "" {
		return false, ErrInvalidArgument
	}
	resolved := false
	err := r.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Match bulk revocation lock ordering, including both families even when
		// the source refresh transaction has not inserted its proof yet.
		families := []string{sourceFamily, evicted}
		sort.Strings(families)
		for _, family := range families {
			if err := lockTokenFamily(tx, family); err != nil {
				return err
			}
		}
		var source model.OAuthRefreshToken
		result := tx.Where("token_hash = ? AND user_id = ? AND family_id = ?", tokenHash, userID, sourceFamily).Limit(1).Find(&source)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			// Keep an in-flight rotation pending. Once its proposed token has expired,
			// a late commit cannot authorize a usable session and cannot justify eviction.
			// Family retention keeps every refresh row while ANY family member can
			// still refresh, so proof cannot disappear beneath an active family.
			resolved = !now.Before(sourceExpiry)
			return nil
		}
		var foreign int64
		if err := tx.Model(&model.OAuthRefreshToken{}).Where("family_id = ? AND user_id <> ?", evicted, userID).Count(&foreign).Error; err != nil {
			return err
		}
		if foreign == 0 {
			if err := tx.Model(&model.OAuthAccessToken{}).Where("family_id = ? AND user_id <> ?", evicted, userID).Count(&foreign).Error; err != nil {
				return err
			}
		}
		if foreign != 0 {
			return fmt.Errorf("device eviction family owner mismatch")
		}
		if _, err := revokeFamilyInTransaction(tx, evicted, now); err != nil {
			return err
		}
		resolved = true
		return nil
	})
	return resolved, err
}

package shared

import (
	"context"
	"time"
)

type deviceOperationKey struct{}

// DeviceOperation proves which committed token issuance caused a Redis device
// mutation. A refresh stages Redis work before the DB rotation: reconciliation
// must observe this exact refresh token, not merely any live token in the family.
type DeviceOperation struct {
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

func WithDeviceOperation(ctx context.Context, tokenHash string, expiresAt time.Time) context.Context {
	return context.WithValue(ctx, deviceOperationKey{}, DeviceOperation{tokenHash, expiresAt})
}
func DeviceOperationFromContext(ctx context.Context) DeviceOperation {
	op, _ := ctx.Value(deviceOperationKey{}).(DeviceOperation)
	return op
}

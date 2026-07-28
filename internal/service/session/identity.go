package session

import "context"

// ListIdentities returns the caller's own third-party bindings.
func (s Service) ListIdentities(ctx context.Context, input ListIdentitiesInput) (*ListIdentitiesResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	identities, err := s.Identities.ListByUser(ctx, input.UserID)
	if err != nil {
		return nil, newError(ErrInternal, "查询第三方绑定列表失败", err)
	}
	result := make([]IdentityDTO, 0, len(identities))
	for _, identity := range identities {
		result = append(result, identityDTO(identity))
	}
	return &ListIdentitiesResult{Identities: result}, nil
}

package service

func stringPtr(v string) *string {
	return &v
}

func stringValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

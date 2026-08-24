package turnstile

// SetEndpointForTest redirects a client at a stub siteverify.
//
// Exported through an export_test file so it exists only in tests: the endpoint
// stays a constant in production, where a configurable verification URL would be
// a way to point the only anonymous-write guard at an attacker-controlled
// server. Overriding the address rather than injecting a fake verifier keeps the
// request-building path — form encoding, method, content type, response
// classification — inside the test instead of stubbed past.
func SetEndpointForTest(client *Client, endpoint string) {
	client.endpoint = endpoint
}

package op

var (
	defaultDiscoveryEndpoint     = "/.well-known/openid-configuration"
	defaultAuthorizationEndpoint = "/authorize"
	defaultUserinfoEndpoint      = "/userinfo"
	defaultJSONWebKeysEndpoint   = "/.well-known/jwks.json"
	defaultTokenEndpoint         = "/token"
)

func (pro *Provider) GetDiscoveryEndpoint() string {
	return defaultDiscoveryEndpoint
}

func (pro *Provider) SetDiscoveryEndpoint(newEndpoint string) string {
	defaultDiscoveryEndpoint = newEndpoint
	return newEndpoint
}

func (pro *Provider) GetUserinfoEndpoint() string {
	return defaultUserinfoEndpoint
}

func (pro *Provider) SetUserinfoEndpoint(newEndpoint string) string {
	defaultUserinfoEndpoint = newEndpoint
	return newEndpoint
}

func (pro *Provider) GetJwkEndpoint() string {
	return defaultJSONWebKeysEndpoint
}

func (pro *Provider) SetJwkEndpoint(newEndpoint string) string {
	defaultJSONWebKeysEndpoint = newEndpoint
	return newEndpoint
}

func (pro *Provider) GetAuthorizationEndpoint() string {
	return defaultAuthorizationEndpoint
}

func (pro *Provider) SetAuthorizationEndpoint(newEndpoint string) string {
	defaultAuthorizationEndpoint = newEndpoint
	return newEndpoint
}

func (pro *Provider) GetTokenEndpoint() string {
	return defaultTokenEndpoint
}

func (pro *Provider) SetTokenEndpoint(newEndpoint string) string {
	defaultTokenEndpoint = newEndpoint
	return newEndpoint
}

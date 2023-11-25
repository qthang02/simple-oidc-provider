package oidc

type DiscoveryConfiguration struct {
	Issuer                 string   `json:"issuer,omitempty"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint,omitempty"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	JwksURI                string   `json:"jwks_uri,omitempty"`
	TokenEndpoint          string   `json:"token_endpoint"`
}

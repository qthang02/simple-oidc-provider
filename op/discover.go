package op

import (
	"oidc/oidc"
)

const (
	ScopeOpenID             = "openid"
	ScopeProfile            = "profile"
	ScopeEmail              = "email"
	ScopeAddress            = "address"
	ScopePhone              = "phone"
	ScopeOfflineAccess      = "offline_access"
	ResponseTypeCode        = "code"
	ResponseTypeIDToken     = "id_token token"
	ResponseTypeIDTokenOnly = "id_token"
)

func (pro *Provider) DiscoverHandler() *oidc.DiscoveryConfiguration {
	return &oidc.DiscoveryConfiguration{
		Issuer:                 pro.Issuer,
		AuthorizationEndpoint:  pro.Issuer + pro.GetAuthorizationEndpoint(),
		UserinfoEndpoint:       pro.Issuer + pro.GetUserinfoEndpoint(),
		ScopesSupported:        DefaultSupportedScopes,
		ResponseTypesSupported: DefaultResponseTypes,
		JwksURI:                pro.Issuer + pro.GetJwkEndpoint(),
		TokenEndpoint:          pro.Issuer + pro.GetTokenEndpoint(),
	}
}

var DefaultSupportedScopes = []string{
	ScopeOpenID,
	ScopeProfile,
	ScopeEmail,
	ScopePhone,
	ScopeAddress,
	ScopeOfflineAccess,
}

var DefaultResponseTypes = []string{
	ResponseTypeCode,
	ResponseTypeIDToken,
	ResponseTypeIDTokenOnly,
}

package oidc

type ExchangeTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
	GrantType    string `json:"grant_type"`
	CodeVerifier string `json:"code_verifier"`
}

type ExchangeTokenResponse struct {
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int64  `json:"expires_in"`
}

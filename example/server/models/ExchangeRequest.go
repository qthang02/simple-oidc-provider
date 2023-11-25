package models

type ExchangeRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
	GrantType    string `json:"grant_type"`
	CodeVerifier string `json:"code_verifier"`
}

func NewTokenRequest(clientId, clientSecret, redirectURI, code, grantType string) *ExchangeRequest {
	return &ExchangeRequest{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Code:         code,
		GrantType:    grantType,
	}
}

func (ex *ExchangeRequest) GetClientID() string {
	return ex.ClientID
}

func (ex *ExchangeRequest) GetClientSecret() string {
	return ex.ClientSecret
}

func (ex *ExchangeRequest) GetRedirectURI() string {
	return ex.RedirectURI
}

func (ex *ExchangeRequest) GetCode() string {
	return ex.Code
}

func (ex *ExchangeRequest) GetGrantType() string {
	return ex.GrantType
}

func (ex *ExchangeRequest) GetCodeVerifier() string {
	return ex.CodeVerifier
}

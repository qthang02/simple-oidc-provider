package oidc

import (
	"encoding/json"
)

type AuthorizeRequest struct {
	Scopes       []string `json:"scope"`
	ResponseType string   `json:"response_type"`
	ClientID     string   `json:"client_id"`
	RedirectURI  string   `json:"redirect_uri"`
	State        string   `json:"state"`
	Nonce        string   `json:"nonce"`
}

//type AuthorizeResponse struct {
//	RequestID string    `json:"request_id"`
//	Client    op.Client `json:"client"`
//}

type CallbackRequest struct {
	RequestID  string `json:"request_id"`
	AuthUserID string `json:"auth_user_id"`
}

type CallbackResponse struct {
	RedirectURI string `json:"redirect_uri"`
	Code        string `json:"code"`
	State       string `json:"state"`
}

type AuthorizationCodeMetadata struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	AuthUserID  string `json:"auth_user_id"`
}

func (authMeta *AuthorizationCodeMetadata) MarshalBinary() ([]byte, error) {
	return json.Marshal(authMeta)
}

package models

import (
	"encoding/json"
)

type AuthorizeRequest struct {
	Scopes       []string `json:"scope,omitempty"`
	ResponseType string   `json:"response_type,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	RedirectURI  string   `json:"redirect_uri,omitempty"`
	State        string   `json:"state,omitempty"`
	Nonce        string   `json:"nonce,omitempty"`
}

func NewAuthorizeRequest(clientId, state, nonce, responseType, redirectURI string, scopes []string) *AuthorizeRequest {
	return &AuthorizeRequest{
		ClientID:     clientId,
		Scopes:       scopes,
		ResponseType: responseType,
		RedirectURI:  redirectURI,
		State:        state,
		Nonce:        nonce,
	}
}

func (authReq *AuthorizeRequest) MarshalBinary() ([]byte, error) {
	return json.Marshal(authReq)
}

func (authReq *AuthorizeRequest) GetClientID() string {
	return authReq.ClientID
}

func (authReq *AuthorizeRequest) GetScopes() []string {
	return authReq.Scopes
}

func (authReq *AuthorizeRequest) GetResponseType() string {
	return authReq.ResponseType
}

func (authReq *AuthorizeRequest) GetRedirectURI() string {
	return authReq.RedirectURI
}

func (authReq *AuthorizeRequest) GetState() string {
	return authReq.State
}

func (authReq *AuthorizeRequest) GetNonce() string {
	return authReq.Nonce
}

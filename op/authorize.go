package op

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"oidc/oidc"
)

var (
	ErrNotAllowedResponseType = errors.New("your response type is not allowed")
	ErrNotAllowedScopes       = errors.New("your scopes are not allowed")
	ErrEmptyRedirectURI       = errors.New("your redirect uri is empty")
	ErrMissingAuthUser        = errors.New("missing authorize models")
	ErrMissingRequestID       = errors.New("missing RequestID")
	ErrMissingClientID        = errors.New("missing clientID")
	ErrMissingScopes          = errors.New("missing scopes")
	ErrMissingResponseType    = errors.New("missing response type")
	ErrMissingRedirectURI     = errors.New("missing redirect uri")
	ErrCreateCode             = errors.New("cannot create code")
)

type AuthorizeRequest interface {
	GetClientID() string
	GetScopes() []string
	GetResponseType() string
	GetRedirectURI() string
	GetState() string
	GetNonce() string
}

type AuthorizeResponse struct {
	RequestID string `json:"request_id"`
	Client    Client `json:"client"`
}

func (pro *Provider) Authorize(ctx context.Context, request AuthorizeRequest) (*AuthorizeResponse, error) {
	client, err := pro.validateAuthorizeRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	requestID := uuid.NewString()

	err = pro.rc.SetAuthorizeRequest(ctx, requestID, request)
	if err != nil {
		return nil, err
	}

	return &AuthorizeResponse{
		RequestID: requestID,
		Client:    client,
	}, nil
}

type Client interface {
	GetID() string
	GetRedirectURI() []string
	GetNonce() string
	GetState() string
	GetSecret() string
}

func (pro *Provider) validateAuthorizeRequest(ctx context.Context, request AuthorizeRequest) (Client, error) {
	if pro.NotAllowedResponseType(request.GetResponseType()) {
		return nil, ErrNotAllowedResponseType
	}

	if pro.NotAllowedScopes(request.GetScopes()) {
		return nil, ErrNotAllowedScopes
	}

	client, err := pro.cs.GetClientWithID(ctx, request.GetClientID())
	if err != nil {
		return nil, err
	}

	if pro.AllowRedirectURI(request.GetRedirectURI(), client) {
		return nil, ErrEmptyRedirectURI
	}

	return client, nil
}

func (pro *Provider) NotAllowedResponseType(responseType string) bool {
	for _, v := range DefaultResponseTypes {
		if responseType == v {
			return false
		}
	}
	return true
}

func (pro *Provider) NotAllowedScopes(scopes []string) bool {
	m := make(map[string]bool)

	for _, v := range DefaultSupportedScopes {
		m[v] = true
	}

	for _, v := range scopes {
		isAllow, _ := m[v]

		if !isAllow {
			return true
		}
	}

	return false
}

func (pro *Provider) AllowRedirectURI(redirectURI string, client Client) bool {
	for _, v := range client.GetRedirectURI() {
		if v != redirectURI {
			return true
		}
	}
	return false
}

type CallbackRequest interface {
	GetRequestID() string
	GetAuthUserID() string
}

type CallbackResponse struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
	Code        string `json:"code,omitempty"`
	State       string `json:"state,omitempty"`
}

func (pro *Provider) CallBack(ctx context.Context, request CallbackRequest) (*CallbackResponse, error) {
	authorizeRequest, err := pro.validateCallbackRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	authorizeCode, err := pro.crypto.Encrypt(request.GetRequestID())
	if err != nil {
		return nil, ErrCreateCode
	}

	err = pro.rc.SetAuthorizationCode(ctx, authorizeCode, &oidc.AuthorizationCodeMetadata{
		ClientID:    authorizeRequest.ClientID,
		RedirectURI: authorizeRequest.RedirectURI,
		AuthUserID:  request.GetAuthUserID(),
	})
	if err != nil {
		return nil, err
	}

	return &CallbackResponse{
		RedirectURI: authorizeRequest.RedirectURI,
		Code:        authorizeCode,
		State:       authorizeRequest.State,
	}, nil
}

func (pro *Provider) validateCallbackRequest(ctx context.Context, request CallbackRequest) (*oidc.AuthorizeRequest, error) {
	if len(request.GetAuthUserID()) == 0 {
		return nil, ErrMissingAuthUser
	}

	if len(request.GetRequestID()) == 0 {
		return nil, ErrMissingRequestID
	}

	authorizeRequest, err := pro.rc.GetAuthorizeRequest(ctx, request.GetRequestID())
	if err != nil {
		return nil, err
	}

	if authorizeRequest.ClientID == "" {
		return nil, ErrMissingClientID
	}

	if len(authorizeRequest.Scopes) == 0 {
		return nil, ErrMissingScopes
	}

	if authorizeRequest.ResponseType == "" {
		return nil, ErrMissingResponseType
	}

	if authorizeRequest.RedirectURI == "" {
		return nil, ErrMissingRedirectURI
	}

	return authorizeRequest, nil
}

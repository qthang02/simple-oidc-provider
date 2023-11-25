package oidc

type Client struct {
	ClientID            string   `json:"client_id,omitempty"`
	ClientSecret        string   `json:"client_secret,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
	State               string   `json:"state,omitempty"`
	AllowedRedirectURIs []string `json:"allowed_redirect_uris,omitempty"`
}

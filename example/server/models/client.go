package models

const (
	clientID     = "65fz98Q_heGL7S6uVAunZg"                      //os.Getenv("GOOGLE_OAUTH2_CLIENT_ID")
	clientSecret = "u1A4sYahRxJcLMox1WZF9-OLWAtIqq9wqx26uhcptl4" //os.Getenv("GOOGLE_OAUTH2_CLIENT_SECRET")
)

type Client struct {
	ClientID            string   `json:"client_id,omitempty"`
	ClientSecret        string   `json:"client_secret,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
	State               string   `json:"state,omitempty"`
	AllowedRedirectURIs []string `json:"allowed_redirect_uris,omitempty"`
}

func NewClient(redirectURL []string) (*Client, error) {
	return &Client{
		ClientID:            clientID,     // hardcode for testing
		ClientSecret:        clientSecret, // hardcode for testing
		AllowedRedirectURIs: redirectURL,
	}, nil
}

func (c *Client) GetID() string {
	return c.ClientID
}

func (c *Client) GetRedirectURI() []string {
	return c.AllowedRedirectURIs
}

func (c *Client) GetNonce() string {
	return c.Nonce
}

func (c *Client) GetState() string {
	return c.State
}

func (c *Client) GetSecret() string {
	return c.ClientSecret
}

package op

import (
	"errors"
	"net/url"

	"github.com/google/uuid"
)

var (
	ErrInvalidIssuerPath        = errors.New("no fragments or query allowed for issuer")
	ErrInvalidIssuerNoIssuer    = errors.New("missing issuer")
	ErrInvalidIssuerURL         = errors.New("invalid url for issuer")
	ErrInvalidIssuerMissingHost = errors.New("host for issuer missing")
	ErrInvalidIssuerHTTPS       = errors.New("scheme for issuer must be `https`")
)

type Provider struct {
	Issuer               string
	crypto               Crypto
	allowedResponseTypes []string // using default
	allowedScopes        []string // using default

	// adapter
	cs IClientStorage
	rc ICache
	us IUserStorage
	ks IKeyStorage
}

type Endpoint interface {
	GetDiscoveryEndpoint() string
	SetDiscoveryEndpoint(newEndpoint string) string
	GetUserinfoEndpoint() string
	SetUserinfoEndpoint(newEndpoint string) string
	GetJwkEndpoint() string
	SetJwkEndpoint(newEndpoint string) string
	GetAuthorizationEndpoint() string
	SetAuthorizationEndpoint(newEndpoint string) string
	GetTokenEndpoint() string
	SetTokenEndpoint(newEndpoint string) string
}

func NewOpenIDProvider(issuer string, allowInsecure bool, clientStore IClientStorage, keyStore IKeyStorage) (*Provider, error) {
	// validate issuer
	err := validateIssuer(issuer, allowInsecure)
	if err != nil {
		return nil, err
	}

	var key [32]byte

	copy(key[:], uuid.NewString())

	return &Provider{
		Issuer: issuer,
		crypto: NewAESCrypto(key),
		rc:     NewDefaultDB("localhost:6379", "", 0),
		cs:     clientStore,
		ks:     keyStore,
	}, nil
}

func validateIssuer(issuer string, allowInsecure bool) error {
	if issuer == "" {
		return ErrInvalidIssuerNoIssuer
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return ErrInvalidIssuerURL
	}
	if u.Host == "" {
		return ErrInvalidIssuerMissingHost
	}
	if u.Scheme != "https" {
		if !devLocalAllowed(u, allowInsecure) {
			return ErrInvalidIssuerHTTPS
		}
	}
	return ValidateIssuerPath(u)
}

func ValidateIssuerPath(issuer *url.URL) error {
	if issuer.Fragment != "" || len(issuer.Query()) > 0 {
		return ErrInvalidIssuerPath
	}
	return nil
}

func devLocalAllowed(url *url.URL, allowInsecure bool) bool {
	if !allowInsecure {
		return false
	}
	return url.Scheme == "http"
}

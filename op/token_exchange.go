package op

import (
	"context"
	"errors"
	"oidc/oidc"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/google/uuid"
)

var (
	ErrClientIDNotMatch    = errors.New("ClientID not match")
	ErrRedirectNotMatch    = errors.New("redirect not match")
	ErrMissingClientSecret = errors.New("missing client secret")
	ErrMissingAuthUserID   = errors.New("missing auth user id")
)

type ExchangeRequest interface {
	GetClientID() string
	GetClientSecret() string
	GetRedirectURI() string
	GetCode() string
	GetGrantType() string
	GetCodeVerifier() string
}

func (pro *Provider) ExchangeToken(ctx context.Context, request ExchangeRequest) (*oidc.ExchangeTokenResponse, error) {
	client, err := pro.validateExchangeTokenRequest(ctx, request)
	if err != nil {
		return nil, err
	}

	idToken, err := pro.newIDToken(ctx, client)
	if err != nil {
		return nil, err
	}

	// TODO: New another information here: access token, refresh token, expire,..

	accessToken, err := pro.crypto.Encrypt(uuid.NewString() + ":" + "id1")

	return &oidc.ExchangeTokenResponse{
		IDToken:     idToken,
		AccessToken: accessToken,
		ExpiresIn:   time.Now().Add(24 * time.Hour).Unix(),
	}, nil
}

func (pro *Provider) validateExchangeTokenRequest(ctx context.Context, request ExchangeRequest) (Client, error) {
	codeCM, err := pro.rc.GetAuthorizationCode(ctx, request.GetCode())
	if err != nil {
		return nil, err
	}

	client, err := pro.cs.GetClientWithCredentials(ctx, request.GetClientID(), request.GetClientSecret())
	if err != nil {
		return nil, err
	}

	if err = pro.validateClientMetaData(client, codeCM); err != nil {
		return nil, err
	}

	//authUser, err := pro.us.GetUserWithID(ctx, codeCM.AuthUserID)
	//if err != nil {
	//	return nil, nil, err
	//}

	return client, nil
}

func (pro *Provider) validateClientMetaData(client Client, request *oidc.AuthorizationCodeMetadata) error {
	if client.GetID() != request.ClientID {
		return ErrClientIDNotMatch
	}

	for _, v := range client.GetRedirectURI() {
		if v != request.RedirectURI {
			return ErrRedirectNotMatch
		}
	}

	if client.GetSecret() == "" {
		return ErrMissingClientSecret
	}

	if request.AuthUserID == "" {
		return ErrMissingAuthUserID
	}

	return nil
}

func (pro *Provider) newIDToken(ctx context.Context, client Client) (string, error) {
	// private key
	signingKey, err := pro.ks.GetSigningKeyByClient(ctx, client.GetID())
	if err != nil {
		return "", err
	}

	//claims, err := pro.newIDTokenClaims(ctx, client, userInfo)
	//if err != nil {
	//	return "", err
	//}

	token := jwt.New(jwt.SigningMethodRS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = "Thang"
	claims["given_name"] = "Quoc"
	claims["family_name"] = "Nguyen"
	claims["nickname"] = "thang02"
	claims["email"] = "thang02@example.com"
	claims["email_verified"] = true
	claims["picture"] = "https://example.com/thang02/me.jpg"
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	claims["iss"] = "http://localhost:9090"
	claims["aud"] = client.GetID()
	claims["sub"] = "1234567890"
	claims["iat"] = time.Now().Unix()
	claims["jti"] = "1234567890"
	claims["nonce"] = client.GetNonce()

	idToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return idToken, nil
}

//func (pro *Provider) newIDTokenClaims(ctx context.Context, client Client, userInfo *oidc.UserInfo) (*oidc.IDTokenClaims, error) {
//	//claims := oidc.NewIDTokenClaims(client, userInfo)
//
//	//ttl, err := pro.as.GetTokenTTLByClient(ctx, client.ClientID)
//	//if err != nil {
//	//	return nil, err
//	//}
//	return claims, nil
//}

//func (pro *Provider) GenerateToken(ttl time.Duration, payload interface{}, client *oidc.Client) (string, error) {
//	token := jwt.New(jwt.SigningMethodHS256)
//
//	now := time.Now().UTC()
//	claims := token.Claims.(jwt.MapClaims)
//
//	claims["sub"] = payload
//	claims["exp"] = now.Add(ttl).Unix()
//	claims["iat"] = now.Unix()
//	claims["nbf"] = now.Unix()
//
//	tokenString, err := token.SignedString([]byte(client.ClientSecret))
//
//	if err != nil {
//		return "", fmt.Errorf("generating JWT Token failed: %w", err)
//	}
//
//	return tokenString, nil
//}
//
//func (pro *Provider) ValidateToken(token string, client *oidc.Client) (interface{}, error) {
//	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
//		if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); !ok {
//			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
//		}
//
//		return []byte(client.ClientSecret), nil
//	})
//	if err != nil {
//		return nil, fmt.Errorf("invalidate token: %w", err)
//	}
//
//	claims, ok := tok.Claims.(jwt.MapClaims)
//	if !ok || !tok.Valid {
//		return nil, fmt.Errorf("invalid token claim")
//	}
//
//	return claims["sub"], nil
//}

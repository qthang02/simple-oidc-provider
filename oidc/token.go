package oidc

import (
	"github.com/go-jose/go-jose/v3/jwt"
	"time"
)

type IDTokenClaims struct {
	jwt.Claims
	Userinfo *UserInfo
}

func NewIDTokenClaims(client *Client, userInfo *UserInfo) *IDTokenClaims {
	return &IDTokenClaims{
		Claims: jwt.Claims{
			Issuer:   "http://localhost:9090",
			Audience: jwt.Audience{client.ClientID},
			Expiry:   jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
		Userinfo: userInfo,
	}
}

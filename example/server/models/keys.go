package models

import (
	"context"
	"crypto/rsa"
	"time"
)

type signingKey struct {
	PrivateKey *rsa.PrivateKey
}

func NewSigningKey() *signingKey {
	return &signingKey{}
}

func (sk *signingKey) GetSigningKeyByClient(ctx context.Context, clientID string) (*rsa.PrivateKey, error) {
	return sk.PrivateKey, nil
}

func (sk *signingKey) GetTokenTTLByClient(ctx context.Context, clientID string) (time.Time, error) {
	panic("")
}

package storage

import (
	"context"
	"errors"
	"fmt"
	"oidc/example/server/models"
	"oidc/op"
)

var (
	ErrCannotFoundClient = errors.New("cannot found client")
	ErrSecretNotMatch    = errors.New("client secret not match")
)

type ClientStore struct {
	storage map[string]*models.Client
}

func NewClientStore(c *models.Client) *ClientStore {
	return &ClientStore{
		storage: map[string]*models.Client{
			c.ClientID: c,
		},
	}
}

func (cs *ClientStore) GetClientWithID(ctx context.Context, clientID string) (op.Client, error) {
	client, isExit := cs.storage[clientID]
	if !isExit {
		return nil, ErrCannotFoundClient
	}

	return client, nil
}

func (cs *ClientStore) GetClientWithCredentials(ctx context.Context, clientID string, clientSecret string) (op.Client, error) {
	fmt.Println("clientID: ", clientID)

	client, isExit := cs.storage[clientID]
	if !isExit {
		return nil, ErrCannotFoundClient
	}

	if clientSecret != client.ClientSecret {
		return nil, ErrSecretNotMatch
	}

	return client, nil
}

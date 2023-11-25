package storage

import (
	"context"
	"errors"
	"oidc/example/server/models"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type UserStore struct {
	Storage map[string]*models.User
}

func (us *UserStore) GetUserWithID(ctx context.Context, userID string) (*models.User, error) {
	user, isExit := us.Storage[userID]
	if !isExit {
		return nil, ErrUserNotFound
	}

	return user, nil
}

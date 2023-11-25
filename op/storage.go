package op

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"oidc/oidc"
	"time"

	"github.com/go-redis/redis"
)

type IClientStorage interface {
	GetClientWithID(ctx context.Context, clientID string) (Client, error)
	GetClientWithCredentials(ctx context.Context, clientID string, clientSecret string) (Client, error)
}

type IUserStorage interface {
	GetUserWithID(ctx context.Context, userID string) (*oidc.UserInfo, error)
}

type IKeyStorage interface {
	GetSigningKeyByClient(ctx context.Context, clientID string) (*rsa.PrivateKey, error)
	GetTokenTTLByClient(ctx context.Context, clientID string) (time.Time, error)
}

type ICache interface {
	SetAuthorizeRequest(ctx context.Context, requestID string, request AuthorizeRequest) error
	DeleteAuthorizeRequest(ctx context.Context, requestID string) error
	GetAuthorizeRequest(ctx context.Context, requestID string) (*oidc.AuthorizeRequest, error)
	SetAuthorizationCode(ctx context.Context, authorizeCode string, metadata *oidc.AuthorizationCodeMetadata) error
	DeleteAuthorizationCode(ctx context.Context, authorizeCode string) error
	GetAuthorizationCode(ctx context.Context, authorizeCode string) (*oidc.AuthorizationCodeMetadata, error)
}

type DefaultStorage struct {
	redis *redis.Client
}

func NewDefaultDB(addr string, pass string, db int) *DefaultStorage {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: pass,
		DB:       db,
	})

	return &DefaultStorage{redis: rdb}
}

func (db *DefaultStorage) SetAuthorizeRequest(ctx context.Context, requestID string, request AuthorizeRequest) error {
	err := db.redis.Set(requestID, request, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

func (db *DefaultStorage) DeleteAuthorizeRequest(ctx context.Context, requestID string) error {
	err := db.redis.Del(requestID).Err()
	if err != nil {
		return err
	}
	return nil
}

func (db *DefaultStorage) GetAuthorizeRequest(ctx context.Context, requestID string) (*oidc.AuthorizeRequest, error) {
	//var reps AuthorizeRequest

	data, err := db.redis.Get(requestID).Result()
	if err != nil {
		return nil, err
	}

	response := oidc.AuthorizeRequest{}

	err = json.Unmarshal([]byte(data), &response)
	if err != nil {
		panic(err)
	}

	return &response, nil
}

func (db *DefaultStorage) SetAuthorizationCode(ctx context.Context, authorizeCode string, metadata *oidc.AuthorizationCodeMetadata) error {
	err := db.redis.Set(authorizeCode, metadata, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

func (db *DefaultStorage) DeleteAuthorizationCode(ctx context.Context, authorizeCode string) error {
	err := db.redis.Del(authorizeCode).Err()
	if err != nil {
		return err
	}
	return nil
}

func (db *DefaultStorage) GetAuthorizationCode(ctx context.Context, authorizeCode string) (*oidc.AuthorizationCodeMetadata, error) {
	var req oidc.AuthorizationCodeMetadata

	fmt.Println("authorizeCode: ", authorizeCode)

	value, err := db.redis.Get(authorizeCode).Result()
	if err != nil {
		fmt.Print("err-1: ", err)
		return nil, err
	}

	err = json.Unmarshal([]byte(value), &req)
	if err != nil {
		return nil, err
	}

	return &req, nil
}

package oidc

import (
	"time"
)

type UserInfo struct {
	UserId     string     `json:"user_id"`
	Name       string     `json:"name"`
	GivenName  string     `json:"given_name"`
	FamilyName string     `json:"family_name"`
	MiddleName string     `json:"middle_name"`
	Nickname   string     `json:"nickname"`
	Gender     string     `json:"gender"`
	Password   string     `json:"password"`
	Country    string     `json:"country"`
	Local      string     `json:"local"`
	CreatedAt  *time.Time `json:"created_at"`
}

type UserInfoRequest struct {
	AccessToken string `schema:"access_token"`
}

package models

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
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

func NewUser(nickName, name, pass, gender, familyName, giveName, country, local string) *User {
	return &User{
		UserId:     uuid.NewString(),
		Nickname:   nickName,
		Name:       name,
		MiddleName: giveName,
		FamilyName: familyName,
		Gender:     gender,
		Country:    country,
		Local:      local,
		Password:   pass,
	}
}

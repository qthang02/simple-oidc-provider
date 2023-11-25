package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/postgres"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const (
	clientID     = "65fz98Q_heGL7S6uVAunZg"                      //os.Getenv("GOOGLE_OAUTH2_CLIENT_ID")
	clientSecret = "u1A4sYahRxJcLMox1WZF9-OLWAtIqq9wqx26uhcptl4" //os.Getenv("GOOGLE_OAUTH2_CLIENT_SECRET")
)

type Profile struct {
	Username  string `json:"username"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

var profile Profile

func main() {
	var state string
	var nonce string
	var idTokenHint string
	var logoutToken string

	ctx := context.Background()
	r := gin.Default()
	r.LoadHTMLGlob("./templates/*")

	db, err := sql.Open("postgres", "postgresql://postgres:secret@localhost:5432/session-client1?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	store, err := postgres.NewStore(db, []byte("secret"))
	if err != nil {
		log.Fatal(err)
	}

	r.Use(sessions.Sessions("mysession", store))

	provider, err := oidc.NewProvider(ctx, "http://localhost:9090")
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:5556/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	r.GET("/", func(c *gin.Context) {
		data, _ := getSessionData(db, "key01")

		if data == "" {
			// redender login templates
			c.HTML(http.StatusOK, "login.html", gin.H{
				"title": "Login page",
			})
		} else {
			// err = json.Unmarshal([]byte(idTokenHint), &profile)
			// if err != nil {
			// 	c.JSON(http.StatusInternalServerError, gin.H{
			// 		"message": "failed to unmarshal id_token claims",
			// 	})
			// 	return
			// }

			// render profile templates
			c.HTML(http.StatusOK, "profile.html", gin.H{
				"name":      "NguyenQuoc Thang",
				"username":  "qthang",
				"firstname": "Quoc Thang",
				"lastname":  "Nguyen",
				"email":     "nguyenquocthang909@gmail.com",
			})
		}
	})

	r.GET("/login", func(c *gin.Context) {
		state, err = randString(16)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "failed to generate state",
			})
			return
		}

		nonce, err = randString(16)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "failed to generate nonce",
			})
			return
		}

		c.Redirect(http.StatusFound, config.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce)))
	})

	r.GET("/auth/callback", func(c *gin.Context) {
		if state != c.Query("state") {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "state did not match",
			})
			return
		}

		oauth2Token, err := config.Exchange(ctx, c.PostForm("code"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "failed to exchange token",
			})
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "no id_token field in oauth2 token",
			})
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "failed to verify id_token",
			})
			return
		}

		if idToken.Nonce != nonce {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "nonce did not match",
			})
			return
		}

		oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "failed to parse id_token claims",
			})
			return
		}

		data, err := json.Marshal(&resp.IDTokenClaims)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "failed to marshal id_token claims",
			})
			return
		}

		idTokenHint = string(data)

		err = insertSession(db, "key01", "some_session_data")
		if err != nil {
			log.Fatal(err)
		}

		c.Redirect(http.StatusFound, "/")
	})

	// rp initial logout
	r.GET("/logout", func(c *gin.Context) {

		c.Redirect(http.StatusFound, "http://localhost:9090/end-session?id_token_hint="+idTokenHint+"&post_logout_redirect_uri=http://localhost:5556/")
	})


	// back-channel logout uri
	r.POST("/back-channel-logout", func(c *gin.Context) {
		
		logoutToken, _ = c.GetPostForm("logout_token")

		err := expireSession(db, "key01")
		if err != nil {
			log.Fatalln(err)
		}
	})

	r.GET("/back-channel-logout", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"token": logoutToken,
		})
	})

	r.Run(":5556")
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func insertSession(db *sql.DB, key, sessionData string) error  {
	_, err := db.Exec("INSERT INTO http_sessions (key, data) VALUES ($1, $2)", key, sessionData)
	if err != nil {
		return err
	}

	return nil
}

func getSessionData(db *sql.DB, key string) (string, error) {
	var data string
	err := db.QueryRow("SELECT data FROM http_sessions WHERE key = $1", key).Scan(&data)
	if err != nil {
		return "", err
	}
	return data, nil
}

func expireSession(db *sql.DB, key string) error {
	_, err := db.Exec("DELETE FROM http_sessions WHERE key = $1", key)
	if err != nil {
		return err
	}
	return nil
}
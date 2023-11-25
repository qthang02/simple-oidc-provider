package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"oidc/example/server/models"
	"oidc/example/server/storage"
	"oidc/op"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {

	r := gin.Default()
	r.LoadHTMLGlob("./templates/*html")

	/// define client storage
	client, err := models.NewClient([]string{"http://localhost:5556/auth/callback"})
	if err != nil {
		log.Fatal(err)
	}

	clientStorage := storage.NewClientStore(client)

	/// define client storage
	user := models.NewUser("thang02", "Thang", "123456", "male", "Nguyen", "Quoc", "VietNam", "HCM")

	// define key storage
	keys := models.NewSigningKey()

	// create new provider
	provider, err := op.NewOpenIDProvider("http://localhost:9090", true, clientStorage, keys)
	if err != nil {
		log.Fatal("cannot create provider")
	}

	// var JWKS *jose.JSONWebKeySet
	privateKeyV1, jwksV1, err := provider.GenerateJWKs()
	if err != nil {
		return
	}

	keys.PrivateKey = privateKeyV1

	// requestID
	requestId := ""

	// setup routing
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login", gin.H{
			"title": "login page",
		})
	})

	r.POST("/login/username", func(c *gin.Context) {
		//username, _ := c.GetPostForm("username")
		//password, _ := c.GetPostForm("password")

		//if username == user.Info.Nickname && password == user.Info.Password {
		//	userStorage[user.Info.UserId] = user
		//} else {
		//	c.JSON(http.StatusNotFound, "user not found")
		//}

		callbackRequest := models.NewCallbackRequest(requestId, user.UserId)

		callbackResponse, err := provider.CallBack(context.Background(), callbackRequest)
		if err != nil {
			c.JSON(http.StatusBadRequest, err)
			return
		}

		// http://localhost:5556/auth/callback?code=abc123&state=xyz456
		redirectURL := fmt.Sprintf("%v?code=%v&state=%v", callbackResponse.RedirectURI, callbackResponse.Code, callbackResponse.State)

		c.Redirect(http.StatusFound, redirectURL)
	})

	r.GET(provider.GetDiscoveryEndpoint(), func(c *gin.Context) {
		c.JSON(http.StatusOK, provider.DiscoverHandler())
	})

	r.GET(provider.GetJwkEndpoint(), func(c *gin.Context) {
		c.JSON(http.StatusOK, jwksV1)
	})

	r.GET(provider.GetAuthorizationEndpoint(), func(c *gin.Context) {
		clientID := c.Query("client_id")
		state := c.Query("state")
		nonce := c.Query("nonce")
		responseType := c.Query("response_type")
		redirectURI := c.Query("redirect_uri")
		scope := c.Query("scope")

		scopes := strings.Split(scope, " ")

		client.State = state
		client.Nonce = nonce

		authorizeRequest := models.NewAuthorizeRequest(clientID, state, nonce, responseType, redirectURI, scopes)
		authorizeResponse, err := provider.Authorize(c, authorizeRequest)
		if err != nil {
			fmt.Println(err)
			return
		}

		requestId = authorizeResponse.RequestID
		fmt.Println(authorizeResponse.Client)

		c.Redirect(http.StatusFound, "http://localhost:9090/login?requestID="+requestId)
	})

	r.POST(provider.GetTokenEndpoint(), func(c *gin.Context) {
		clientId, _ := c.GetPostForm("client_id")
		clientSecret, _ := c.GetPostForm("client_secret")
		redirectURI, _ := c.GetPostForm("redirect_uri")
		code, _ := c.GetPostForm("code")
		grantType, _ := c.GetPostForm("grant_type")

		tokenRequest := models.NewTokenRequest(clientId, clientSecret, redirectURI, code, grantType)

		tokenResponse, err := provider.ExchangeToken(context.Background(), tokenRequest)
		if err != nil {
			fmt.Println(err)
			return
		}

		c.JSON(http.StatusOK, tokenResponse)
	})

	err = r.Run(":9090")
	if err != nil {
		return
	}

}

package handlers

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ksysoev/bouncer/pkg/models"
	"gopkg.in/yaml.v3"
)

type ServiceConfig struct {
	PublicKeys []string `yaml:"public_keys"`
	PrivateKey string   `yaml:"private_key"`
}

type AppConfig struct {
	Services     map[string]ServiceConfig `yaml:"services"`
	Certificates ServiceConfig            `yaml:"certificates"`
}

// App is the application, that contains all the handlers
type App struct {
	AppConfig AppConfig
}

func (a *App) LoadPublicKeys(configFile string) error {
	fileData, err := ioutil.ReadFile(configFile)

	if err != nil {
		return err
	}

	err = yaml.Unmarshal(fileData, &a.AppConfig)

	return err
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

// Token is the handler for /token endpoint, that will return jwt token
func (a *App) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Parse authorize token
	authHeader := r.Header.Get("Authorization")
	token_type := authHeader[0:6]

	if token_type != "Bearer" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwt_token := authHeader[7:]

	refreshToken, err := models.ParseRefreshToken(jwt_token, a.AppConfig.Certificates.PrivateKey)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	accessToken, err := models.GenerateAccessToken(refreshToken, a.AppConfig.Certificates.PrivateKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var tokenResponse TokenResponse
	tokenResponse.AccessToken = accessToken

	response, err := json.Marshal(tokenResponse)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

type ValidateTokenResponse struct {
	Audience []string `json:"aud"`
	Subject  string   `json:"sub"`
}

// ValidateToken is the handler for /token/validate endpoint, that will validate jwt token
func (a *App) ValidateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Parse authorize token
	authHeader := r.Header.Get("Authorization")
	tokenType := authHeader[0:6]

	if tokenType != "Bearer" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	accessToken := authHeader[7:]

	var token *jwt.Token
	var err error

	for _, publicKey := range a.AppConfig.Certificates.PublicKeys {
		token, err = models.ParseAccessToken(accessToken, publicKey)
		if err != nil {
			continue
		}
	}

	if token == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var response ValidateTokenResponse

	// Token is issued by us, right? probably we can trust it for now, but I should improve this
	response.Subject, _ = token.Claims.GetSubject()
	response.Audience, _ = token.Claims.GetAudience()

	responseString, err := json.Marshal(response)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseString)
}

// PublicKeys is the handler for /public_keys endpoint that will return public keys
func (a *App) PublicKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	certs := a.AppConfig.Certificates

	publicKeys := certs.PublicKeys

	response, err := json.Marshal(publicKeys)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)

}

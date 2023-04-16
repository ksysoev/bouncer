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
	UserModel *models.UserModel
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

func getAuthorizeToken(r *http.Request) string {
	if r.Header.Get("Authorization") == "" {
		return ""
	}

	//Parse authorize token
	authHeader := r.Header.Get("Authorization")

	if len(authHeader) < 7 {
		return ""
	}

	token_type := authHeader[0:6]

	if token_type != "Bearer" {
		return ""
	}

	jwt_token := authHeader[7:]

	return jwt_token
}

// Token is the handler for /token endpoint, that will return jwt token
func (a *App) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	jwt_token := getAuthorizeToken(r)
	if jwt_token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refreshToken, err := models.ParseRefreshToken(jwt_token, func(userID string) (string, error) {
		ver, err := a.UserModel.GetVersion(r.Context(), userID)

		if err != nil {
			return "", err
		}

		return a.AppConfig.Certificates.PrivateKey + ver, nil
	})

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

	accessToken := getAuthorizeToken(r)
	if accessToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

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

package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
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

	token, err := jwt.Parse(jwt_token, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		certs := a.AppConfig.Certificates

		publicKey := certs.PublicKeys[0]

		key, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

		return key, nil
	})

	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		log.Println("Invalid token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	aud := token.Claims.(jwt.MapClaims)["aud"]
	sub := token.Claims.(jwt.MapClaims)["sub"]

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "bouncer",
		"sub": sub,
		"aud": aud,
	})

	privateKey := a.AppConfig.Certificates.PrivateKey
	key, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	accessTokenString, err := accessToken.SignedString(key)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var tokenResponse TokenResponse
	tokenResponse.AccessToken = accessTokenString

	response, err := json.Marshal(tokenResponse)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// ValidateToken is the handler for /token/validate endpoint, that will validate jwt token
func (a *App) ValidateToken(w http.ResponseWriter, r *http.Request) {

}

// PublicKeys is the handler for /public_keys endpoint that will return public keys
func (a *App) PublicKeys(w http.ResponseWriter, r *http.Request) {

}

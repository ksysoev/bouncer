package handlers

import (
	"io/ioutil"
	"net/http"

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

type ValidateTokenResponse struct {
	Audience []string `json:"aud"`
	Subject  string   `json:"sub"`
}

package handlers

import (
	"io/ioutil"
	"net/http"

	"gopkg.in/yaml.v3"
)

// App is the application, that contains all the handlers
type App struct {
	publicKeys map[string]string
}

func (a *App) LoadPublicKeys(configFile string) error {
	fileData, err := ioutil.ReadFile(configFile)

	if err != nil {
		return err
	}

	err = yaml.Unmarshal(fileData, &a.publicKeys)

	return err
}

// Token is the handler for /token endpoint, that will return jwt token
func (a *App) Token(w http.ResponseWriter, r *http.Request) {

}

// ValidateToken is the handler for /token/validate endpoint, that will validate jwt token
func (a *App) ValidateToken(w http.ResponseWriter, r *http.Request) {

}

// PublicKeys is the handler for /public_keys endpoint that will return public keys
func (a *App) PublicKeys(w http.ResponseWriter, r *http.Request) {

}

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

const portNumber = ":80"

// App is the application, that contains all the handlers
type App struct {
	publicKeys map[string]string
}

type AuthorizeRequest struct {
	user_id string
}

type AuthorizeResponse struct {
	access_token  string
	refresh_token string
}

func main() {

	publicKeys, err := loadPublicKeys("./config.yml")

	if err != nil {
		log.Fatal(err)
		return
	}

	app := App{publicKeys: publicKeys}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", app.Authorize)
	mux.HandleFunc("/token", app.Token)
	mux.HandleFunc("/token/validate", app.ValidateToken)
	mux.HandleFunc("/public_keys", app.PublicKeys)

	fmt.Println("Stating app at ", portNumber)
	err = http.ListenAndServe(portNumber, mux)
	log.Fatal(err)
}

// Authorize is the handler for /authorize endpoint
// it will validate authorization code and return jwt token
func (a *App) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
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

		iss := token.Claims.(jwt.MapClaims)["iss"]
		serviceName, ok := iss.(string)

		if !ok {
			return nil, fmt.Errorf("unexpected issuer format")
		}

		publicKey := a.publicKeys[serviceName]

		return publicKey, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Println(token)

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

func loadPublicKeys(configFile string) (map[string]string, error) {
	result := make(map[string]string)

	fileData, err := ioutil.ReadFile(configFile)

	if err != nil {
		return result, err
	}

	err = yaml.Unmarshal(fileData, &result)

	return result, err
}

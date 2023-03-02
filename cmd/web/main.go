package main

import (
	"fmt"
	"log"
	"net/http"
)

const portNumber = ":80"

// App is the application, that contains all the handlers
type App struct{}

func main() {
	app := App{}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", app.Authorize)
	mux.HandleFunc("/token", app.Token)
	mux.HandleFunc("/token/validate", app.ValidateToken)
	mux.HandleFunc("/public_keys", app.PublicKeys)

	fmt.Println("Stating app at ", portNumber)
	err := http.ListenAndServe(portNumber, mux)
	log.Fatal(err)
}

// Authorize is the handler for /authorize endpoint
// it will validate authorization code and return jwt token
func (a *App) Authorize(w http.ResponseWriter, r *http.Request) {

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

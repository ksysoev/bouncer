package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ksysoev/bouncer/pkg/handlers"
)

const portNumber = ":80"

func main() {
	app := handlers.App{}
	err := app.LoadPublicKeys("./config.yml")

	if err != nil {
		log.Fatal(err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", app.Authorize)
	mux.HandleFunc("/token", app.Token)
	mux.HandleFunc("/token/validate", app.ValidateToken)
	mux.HandleFunc("/public_keys", app.PublicKeys)

	fmt.Println("Stating app at ", portNumber)
	err = http.ListenAndServe(portNumber, mux)
	log.Fatal(err)
}

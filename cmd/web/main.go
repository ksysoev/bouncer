package main

import (
	"fmt"
	"log"
	"net/http"
)

const portNumber = ":80"

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/token/access", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {})
	//Issue access token
	//Issue refresh token
	//server public key
	fmt.Println("Stating app at ", portNumber)
	err := http.ListenAndServe(portNumber, mux)
	log.Fatal(err)
}

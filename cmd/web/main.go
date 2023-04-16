package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ksysoev/bouncer/pkg/handlers"
	"github.com/ksysoev/bouncer/pkg/models"
	"github.com/redis/go-redis/v9"
)

const portNumber = ":80"

func main() {

	rdx := redis.NewClient(&redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "", // no password set
	})

	userModel := models.NewUserModel(rdx, "", time.Hour*0)

	app := handlers.App{UserModel: userModel}
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
	mux.HandleFunc("/logout", app.Logout)

	fmt.Println("Stating app at ", portNumber)
	err = http.ListenAndServe(portNumber, mux)
	log.Fatal(err)
}

package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type AuthorizeRequest struct {
	user_id string
}

type AuthorizeResponse struct {
	access_token  string
	refresh_token string
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

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Parse request body
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var authorizeRequest AuthorizeRequest

	err = json.Unmarshal(body, &authorizeRequest)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Validate request body
	if authorizeRequest.user_id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Generate jwt token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "bouncer",
		"sub": authorizeRequest.user_id,
		"aud": "service",
	})

	// TODO: Adds loading private key
	var privateKey string

	accessTokenString, err := accessToken.SignedString(privateKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Generate refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "bouncer",
		"sub": authorizeRequest.user_id,
		"aud": "service",
	})

	refreshTokenString, err := refreshToken.SignedString(privateKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Return response
	var authorizeResponse AuthorizeResponse
	authorizeResponse.access_token = accessTokenString
	authorizeResponse.refresh_token = refreshTokenString

	response, err := json.Marshal(authorizeResponse)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

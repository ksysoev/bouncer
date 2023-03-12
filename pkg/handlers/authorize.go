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
	errorCode, _ := a.validateRequest(r)

	if errorCode != 0 {
		w.WriteHeader(errorCode)
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

func (a *App) validateRequest(r *http.Request) (int, any) {
	if r.Method != "POST" {
		return http.StatusMethodNotAllowed, nil
	}

	if r.Header.Get("Content-Type") != "application/json" {
		return http.StatusUnsupportedMediaType, nil
	}

	if r.Header.Get("Authorization") == "" {
		return http.StatusUnauthorized, nil
	}

	//Parse authorize token
	authHeader := r.Header.Get("Authorization")
	token_type := authHeader[0:6]

	if token_type != "Bearer" {
		return http.StatusUnauthorized, nil
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

		// TODO: Need to add logic for handling multiple public keys, that will be needed for key rotation
		publicKey := a.AppConfig.Services[serviceName].PublicKeys[0]

		return publicKey, nil
	})

	if err != nil {
		return http.StatusUnauthorized, nil
	}

	if !token.Valid {
		return http.StatusUnauthorized, nil
	}

	return 0, token
}

package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ksysoev/bouncer/pkg/models"
)

type AuthorizeRequest struct {
	Sub string   `json:"sub"`
	Aud []string `json:"aud"`
}

type AuthorizeResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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
	if authorizeRequest.Sub == "" || len(authorizeRequest.Aud) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authorizeResponse, err := a.generateAuthorizeResponse(authorizeRequest)

	if err != nil {
		log.Println("Error generating authorize response: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

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

		serviceCfg, ok := a.AppConfig.Services[serviceName]

		if !ok {
			return nil, fmt.Errorf("Issuer is unknown %v", iss)
		}

		publicKey := serviceCfg.PublicKeys[0]

		if publicKey == "" {
			return nil, fmt.Errorf("Issuer is unknown %v", iss)
		}

		key, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

		return key, nil
	})

	if err != nil {
		log.Println(err)
		return http.StatusUnauthorized, nil
	}

	if !token.Valid {
		log.Println("Invalid token")
		return http.StatusUnauthorized, nil
	}

	return 0, token
}

func (a *App) generateAuthorizeResponse(request AuthorizeRequest) (AuthorizeResponse, error) {
	//Generate jwt token
	var response AuthorizeResponse

	refreshToken, refreshTokenString, err := models.GenerateRefreshToken(jwt.MapClaims{
		"iss": "bouncer",
		"sub": request.Aud,
		"aud": "service",
	}, a.AppConfig.Certificates.PrivateKey)

	if err != nil {
		return response, err
	}

	accessTokenString, err := models.GenerateAccessToken(refreshToken, a.AppConfig.Certificates.PrivateKey)

	if err != nil {
		return response, err
	}

	response.AccessToken = accessTokenString
	response.RefreshToken = refreshTokenString

	return response, nil

}

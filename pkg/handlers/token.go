package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/ksysoev/bouncer/pkg/models"
)

// Token is the handler for /token endpoint, that will return jwt token
func (a *App) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	jwt_token := getAuthorizeToken(r)
	if jwt_token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refreshToken, err := models.ParseRefreshToken(jwt_token, func(userID string) (string, error) {
		ver, err := a.UserModel.GetVersion(r.Context(), userID)

		if err != nil {
			return "", err
		}

		return a.AppConfig.Certificates.PrivateKey + ver, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	accessToken, err := models.GenerateAccessToken(refreshToken, a.AppConfig.Certificates.PrivateKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var tokenResponse TokenResponse
	tokenResponse.AccessToken = accessToken

	response, err := json.Marshal(tokenResponse)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

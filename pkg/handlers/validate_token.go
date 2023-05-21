package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ksysoev/bouncer/pkg/models"
)

// ValidateToken is the handler for /token/validate endpoint, that will validate jwt token
func (a *App) ValidateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	accessToken := getAuthorizeToken(r)
	if accessToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var token *jwt.Token
	var err error

	for _, publicKey := range a.AppConfig.Certificates.PublicKeys {
		token, err = models.ParseAccessToken(accessToken, publicKey)
		if err != nil {
			continue
		}
	}

	if token == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var response ValidateTokenResponse

	// Token is issued by us, right? probably we can trust it for now, but I should improve this
	response.Subject, _ = token.Claims.GetSubject()
	response.Audience, _ = token.Claims.GetAudience()

	responseString, err := json.Marshal(response)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseString)
}

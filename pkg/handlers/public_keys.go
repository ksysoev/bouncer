package handlers

import (
	"encoding/json"
	"net/http"
)

// PublicKeys is the handler for /public_keys endpoint that will return public keys
func (a *App) PublicKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	certs := a.AppConfig.Certificates

	publicKeys := certs.PublicKeys

	response, err := json.Marshal(publicKeys)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

package handlers

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type LogoutRequest struct {
	Sub string `json:"sub"`
}

type LogoutResponse struct {
	Status string `json:"status"`
}

func (a *App) Logout(w http.ResponseWriter, r *http.Request) {
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

	var logoutRequest LogoutRequest

	err = json.Unmarshal(body, &logoutRequest)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Validate request body
	if logoutRequest.Sub == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, err = a.UserModel.UpdateVersion(r.Context(), logoutRequest.Sub)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logoutrResponse := LogoutResponse{
		Status: "ok",
	}

	response, err := json.Marshal(logoutrResponse)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

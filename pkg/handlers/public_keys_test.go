package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ksysoev/bouncer/pkg/models"
)

func TestApp_PublicKeys(t *testing.T) {
	// Define the test AppConfig and UserModel
	appConfig := AppConfig{
		Certificates: ServiceConfig{
			PublicKeys: []string{"key1", "key2"},
			PrivateKey: "private_key",
		},
	}
	userModel := &models.RedisUserModel{}

	// Define the test App with the test AppConfig and UserModel
	app := &App{
		AppConfig: appConfig,
		UserModel: userModel,
	}

	// Create a test HTTP request
	req, err := http.NewRequest("GET", "/public_keys", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a test HTTP response recorder
	rr := httptest.NewRecorder()

	// Call the PublicKeys handler with the test request and response recorder
	handler := http.HandlerFunc(app.PublicKeys)
	handler.ServeHTTP(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

	// Check the response content type
	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("Handler returned wrong content type: got %v, want %v", ctype, "application/json")
	}

	// Check the response body
	expected := `["key1","key2"]`
	if rr.Body.String() != expected {
		t.Errorf("Handler returned unexpected body: got %v, want %v", rr.Body.String(), expected)
	}
}

func TestApp_PublicKeys_MethodNotAllowed(t *testing.T) {
	// Define the test AppConfig and UserModel
	appConfig := AppConfig{
		Certificates: ServiceConfig{
			PublicKeys: []string{"key1", "key2"},
			PrivateKey: "private_key",
		},
	}
	userModel := &models.RedisUserModel{}

	// Define the test App with the test AppConfig and UserModel
	app := &App{
		AppConfig: appConfig,
		UserModel: userModel,
	}

	// Create a test HTTP request with a non-GET method
	req, err := http.NewRequest("POST", "/public_keys", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a test HTTP response recorder
	rr := httptest.NewRecorder()

	// Call the PublicKeys handler with the test request and response recorder
	handler := http.HandlerFunc(app.PublicKeys)
	handler.ServeHTTP(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Handler returned wrong status code: got %v, want %v", status, http.StatusMethodNotAllowed)
	}
}

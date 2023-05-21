package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ksysoev/bouncer/pkg/models"
	"github.com/stretchr/testify/mock"
)

const testPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5XzVuOJHyvZSU
k+n8oNFb13DfnH8gyZqNh/hPng23JOA+QpHNYjJTbvCXLj0u2ffkcKxMXtoBrOyb
0MevKnE6XyCQCGKCwM3UHQfkaAavKboUdpTDgnUJZACu81kIWbItOWZROruFeXVA
PUzAR7n2Vgn40uxCpebQ9UsIxtmpeHKaM7uJ8pCToCZD1l3A+ZTDc5a0E4pii4ii
7jjsKdhnE4xi5topgq8UR0NvBFj3sQtIenIGqNLlpB0k5f5V3GWZHr3YpwxMwYIs
o+XwV0Xu39yS50o2FpKLPIZUgvwa0YaEOgq3WBYNuuEGM0ch4rtlB7O3vtNQX7rS
xVlr31VhAgMBAAECggEAEl8ELZM/q53sPrlWBCpv9Tkpv4+D7dztCz/BdSqF03O9
IY55YrBrqmchQupbN+x0K9iaysrPskDQBjUvxQVgyVcqI/wgvzKac34ZDSLeHrf0
8Bg8cA/ax354rt4BIdm51c+Ne1llwjmiTCaHF7tEC8zFGjrVHVnRwT2+HPWQFsJk
8ubs9Hh0Ayua/kizQVuJOU2y5cQDl7vM+zi52soCOtjf8UVz+vZrA8qK5CWLKuFz
UPB8iGYlqjPJsJXQhRBcM7aoveHtL8E2PlmQCieO57IbhsUhvvlW86grKiI6+Qt6
LTVNeq4UL45hcxsoyZFiej7ZUOnIRYrpZREQkzbHvQKBgQDb7fmPpitfr+ay6ama
H6DJUa5y2QRb8Gqidr6SxIOhbXD9NbH0aGIWbg4rneQf5nhjs0gOI2ZQHJF+jZnn
V7ldtVx8w/cVBMMmhYtTZOxXlSGEaOYvdiimh4bUY0FVeBXF0cIpEPvldbhpRVhj
kgTDf9DHAYM3Q134xsLTPdLSbwKBgQDXxkkTb9e56SOq2lMsKAkxasvzb5QI+N9n
GRTYCKytlJIrxDCNSnkBP5CHIw1o3GGFKH+Lx7isoV0yYd6/p23ARRRqmlErmO+o
BEfQyrvjEWCRR/kfUVPkK8o8v/jjAi27Y3Y9A6w1GfpPBL4y9FQ2G1GB8jfvy3Pd
3+0EiH39LwKBgQCtfDZ9gzX5wDb6cOmxwztBM2ap/9i5cZecWpEQE2ZGQ596jg23
X1Pon54b9+vI4jObagPv6yq9DRwUOTzrSb7WVccEQE06zkvmqjdybE0m9WPAIENb
sxhz7LqF9VnHQvfh2QoQ/O3HXqo+mE4WFUwer0eQg/fu8vxAzwFGQyF3jwKBgQDM
USUXM5uZngq5GL0THeH+mjr/i1Mo38hjTpuvKR+hygJTURYMZE2Kgg8v92AWQEBT
n5KO4JKdXLrsH0KWRkslegQoIXHlD483kL4UFjStgeHoD7f1EMSYVWLN/ZYGFyUI
wNjQU674JV4g/sO/ah5nkZyvqJWRChzwJr6/wSNT3wKBgF4zQuDyqFmblkzWnmAY
J9oQsbAoIwm71WU60rU4vms2xi7WuADjDpneYQmi+6q4XvdTz16W5jkV0DgciCyL
vD0lw0686jc6zq8eg0h3H6vFZjBbWWbV1j0A7bWYVBk1hXPP0uSOEOjw6HJhXWjy
AzuaKuOn0Reqil1diBctM6UX
-----END PRIVATE KEY-----`

const testPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuV81bjiR8r2UlJPp/KDR
W9dw35x/IMmajYf4T54NtyTgPkKRzWIyU27wly49Ltn35HCsTF7aAazsm9DHrypx
Ol8gkAhigsDN1B0H5GgGrym6FHaUw4J1CWQArvNZCFmyLTlmUTq7hXl1QD1MwEe5
9lYJ+NLsQqXm0PVLCMbZqXhymjO7ifKQk6AmQ9ZdwPmUw3OWtBOKYouIou447CnY
ZxOMYubaKYKvFEdDbwRY97ELSHpyBqjS5aQdJOX+VdxlmR692KcMTMGCLKPl8FdF
7t/ckudKNhaSizyGVIL8GtGGhDoKt1gWDbrhBjNHIeK7ZQezt77TUF+60sVZa99V
YQIDAQAB
-----END PUBLIC KEY-----`

type MockUserModel struct {
	mock.Mock
}

// Implement the GetVersion method of the UserModel interface
func (m *MockUserModel) GetVersion(ctx context.Context, userID string) (string, error) {
	return "0", nil
}

func (u *MockUserModel) UpdateVersion(ctx context.Context, userId string) (string, error) {
	return "0", nil
}

func TestApp_Token(t *testing.T) {
	// Define the test AppConfig and UserModel
	appConfig := AppConfig{
		Certificates: ServiceConfig{
			PublicKeys: []string{testPublicKey},
			PrivateKey: testPrivateKey,
		},
	}

	// Define the test App with the test AppConfig and UserModel
	app := &App{
		AppConfig: appConfig,
		UserModel: &MockUserModel{},
	}

	// Generate valid JWT token

	_, refreshTokenString, _ := models.GenerateRefreshToken(jwt.MapClaims{
		"iss": "bouncer",
		"sub": "123",
		"aud": "service",
	}, testPrivateKey+"0")

	// Create a test HTTP request with a POST method and a valid JWT token
	req, err := http.NewRequest("POST", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+refreshTokenString)

	// Create a test HTTP response recorder
	rr := httptest.NewRecorder()

	// Call the Token handler with the test request and response recorder
	handler := http.HandlerFunc(app.Token)
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
	var tokenResponse TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &tokenResponse)
	if err != nil {
		t.Errorf("Handler returned invalid JSON: %v", err)
	}
	if tokenResponse.AccessToken == "" {
		t.Errorf("Handler returned empty access token")
	}
}

func TestApp_Token_MethodNotAllowed(t *testing.T) {
	// Define the test AppConfig and UserModel
	appConfig := AppConfig{
		Certificates: ServiceConfig{
			PublicKeys: []string{testPublicKey},
			PrivateKey: testPrivateKey,
		},
	}

	// Define the test App with the test AppConfig and UserModel
	app := &App{
		AppConfig: appConfig,
		UserModel: &MockUserModel{},
	}

	// Create a test HTTP request with a non-POST method
	req, err := http.NewRequest("GET", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a test HTTP response recorder
	rr := httptest.NewRecorder()

	// Call the Token handler with the test request and response recorder
	handler := http.HandlerFunc(app.Token)
	handler.ServeHTTP(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Handler returned wrong status code: got %v, want %v", status, http.StatusMethodNotAllowed)
	}
}

func TestApp_Token_Unauthorized(t *testing.T) {
	// Define the test AppConfig and UserModel
	appConfig := AppConfig{
		Certificates: ServiceConfig{
			PublicKeys: []string{testPublicKey},
			PrivateKey: testPrivateKey,
		},
	}

	// Define the test App with the test AppConfig and UserModel
	app := &App{
		AppConfig: appConfig,
		UserModel: &MockUserModel{},
	}

	// Create a test HTTP request with a POST method and an invalid JWT token
	req, err := http.NewRequest("POST", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer invalid_jwt_token")

	// Create a test HTTP response recorder
	rr := httptest.NewRecorder()

	// Call the Token handler with the test request and response recorder
	handler := http.HandlerFunc(app.Token)
	handler.ServeHTTP(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Handler returned wrong status code: got %v, want %v", status, http.StatusUnauthorized)
	}
}

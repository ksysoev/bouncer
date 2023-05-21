package models

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestGenerateRefreshToken(t *testing.T) {
	// Define the claims for the token
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  1516239022,
	}

	// Define the secret for the token
	secret := "mysecret"

	// Generate a refresh token
	token, result, err := GenerateRefreshToken(claims, secret)

	// Assert that no errors occurred
	if err != nil {
		t.Errorf("Error generating refresh token: %v", err)
	}

	// Assert that the token is not nil
	if token == nil {
		t.Error("Refresh token is nil")
	}

	// Assert that the result is not empty
	if result == "" {
		t.Error("Refresh token result is empty")
	}

	// Assert that the token is valid
	parsedToken, err := jwt.Parse(result, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		t.Errorf("Error parsing refresh token: %v", err)
	}
	if !parsedToken.Valid {
		t.Error("Refresh token is not valid")
	}
}

func TestParseRefreshToken(t *testing.T) {
	// Define the token string to parse
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.drt_po6bHhDOF_FJEHTrK-KD8OGjseJZpHwHIgsnoTM"

	// Define the secret generator function
	secretGenerator := func(sub string) (string, error) {
		if sub == "1234567890" {
			return "mysecret", nil
		}
		return "", errors.New("Invalid subject")
	}

	// Parse the refresh token
	token, err := ParseRefreshToken(tokenString, secretGenerator)

	// Assert that no errors occurred
	if err != nil {
		t.Errorf("Error parsing refresh token: %v", err)
		return
	}

	// Assert that the token is not nil
	if token == nil {
		t.Error("Refresh token is nil")
		return
	}

	// Assert that the token is valid
	if !token.Valid {
		t.Error("Refresh token is not valid")
		return
	}

	// Assert that the token has the expected claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Error("Token claims are not of type MapClaims")
		return
	}
	if sub, ok := claims["sub"].(string); !ok || sub != "1234567890" {
		t.Error("Token sub claim is not as expected")
		return
	}
}

func TestGenerateAccessToken(t *testing.T) {
	// Define the refresh token and private key
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["sub"] = "123"
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Generate an access token from the refresh token and private key
	accessToken, err := GenerateAccessToken(refreshToken, testPrivateKey)
	if err != nil {
		t.Errorf("Error generating access token: %v", err)
		return
	}

	// Assert that the access token is not empty
	if accessToken == "" {
		t.Error("Access token is empty")
		return
	}

	// Parse the access token to ensure it is valid
	parsedToken, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		key, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(testPublicKey))

		return key, nil
	})
	if err != nil {
		t.Errorf("Error parsing access token: %v", err)
		return
	}

	// Assert that the access token is valid
	if !parsedToken.Valid {
		t.Error("Access token is not valid")
		return
	}

	// Assert that the access token has the expected claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Error("Token claims are not of type MapClaims")
		return
	}
	if sub, ok := claims["sub"].(string); !ok || sub != "123" {
		t.Error("Token sub claim is not as expected")
		return
	}
}

func TestParseAccessToken(t *testing.T) {
	// Define the public key and access token
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["sub"] = "123"
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Generate an access token from the refresh token and private key
	accessToken, err := GenerateAccessToken(refreshToken, testPrivateKey)
	if err != nil {
		t.Errorf("Error generating access token: %v", err)
		return
	}

	// Parse the access token
	token, err := ParseAccessToken(accessToken, testPublicKey)
	if err != nil {
		t.Errorf("Error parsing access token: %v", err)
		return
	}

	// Assert that the token is not nil
	if token == nil {
		t.Error("Token is nil")
		return
	}

	// Assert that the token is valid
	if !token.Valid {
		t.Error("Token is not valid")
		return
	}

	// Assert that the token claims are correct
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Error("Token claims are not of type MapClaims")
		return
	}
	sub, err := claims.GetSubject()
	if err != nil {
		t.Errorf("Error getting access token subject claim: %v", err)
		return
	}
	if sub != "123" {
		t.Error("Token user_id claim is not as expected")
		return
	}
}

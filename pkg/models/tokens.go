package models

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const AccessTokenExpireTime = 360

func GenerateRefreshToken(claims jwt.MapClaims, secret string) (*jwt.Token, string, error) {
	var token *jwt.Token
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	result, err := token.SignedString([]byte(secret))

	if err != nil {
		return token, "", err
	}

	return token, result, nil
}

func ParseRefreshToken(tokenString string, secret string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("Invalid token")
	}

	return token, nil
}

func GenerateAccessToken(refreshToken *jwt.Token, privateKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshToken.Claims)

	key, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	result, err := token.SignedString(key)

	if err != nil {
		return "", err
	}

	return result, nil
}

func ParseAccessToken(tokenString string, publicKey string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		key, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

		return key, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("Invalid token")
	}

	return token, nil
}

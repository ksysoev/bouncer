package models

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
)

func TestUserModel_GetVersion(t *testing.T) {
	// Create a mock Redis client
	client, mock := redismock.NewClientMock()

	// Define the UserModel with the mock Redis client
	model := &RedisUserModel{
		Redis:  client,
		Prefix: "user:",
		Expiry: time.Hour * 24,
	}

	// Set the expected Redis command and its return value
	mock.ExpectTxPipeline()
	mock.ExpectSetNX("user:123", "0", 0).SetVal(true)
	mock.ExpectExpire("user:123", time.Hour*24).SetVal(true)
	mock.ExpectGet("user:123").SetVal("0")
	mock.ExpectTxPipelineExec()

	// Test the GetVersion method
	version, err := model.GetVersion(context.Background(), "123")
	if err != nil {
		t.Errorf("Error getting version: %v", err)
		return
	}
	if version != "0" {
		t.Errorf("Version is %s, expected 0", version)
		return
	}
}

func TestUserModel_UpdateVersion(t *testing.T) {
	// Create a mock Redis client
	client, mock := redismock.NewClientMock()

	// Define the UserModel with the mock Redis client
	model := &RedisUserModel{
		Redis:  client,
		Prefix: "user:",
		Expiry: time.Hour * 24,
	}

	// Set the expected Redis commands and their return values
	mock.ExpectTxPipeline()
	mock.ExpectIncr("user:123").SetVal(1)
	mock.ExpectExpire("user:123", time.Hour*24).SetVal(true)
	mock.ExpectTxPipelineExec()

	// Test the UpdateVersion method
	version, err := model.UpdateVersion(context.Background(), "123")
	if err != nil {
		t.Errorf("Error updating version: %v", err)
		return
	}
	if version != "1" {
		t.Errorf("Version is %s, expected 1", version)
		return
	}
}

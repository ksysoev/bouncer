package models

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// User is the model for user

// Default values for user model
const userVersionPrefix = "USER::VERSION::"
const versionExpiry = time.Hour * 24 * 30

type UserModel struct {
	Redis  *redis.Client
	Prefix string
	Expiry time.Duration
}

func NewUserModel(redis *redis.Client, prefix string, expiry time.Duration) *UserModel {
	if prefix == "" {
		prefix = userVersionPrefix
	}

	if expiry == 0 {
		expiry = versionExpiry
	}

	return &UserModel{
		Redis:  redis,
		Prefix: prefix,
		Expiry: expiry,
	}
}

// GetVersion returns the version of the user and updates the expiry of the version
func (u *UserModel) GetVersion(ctx context.Context, userId string) (string, error) {
	pipe := u.Redis.TxPipeline()
	var noTTL time.Duration
	_ = pipe.SetNX(ctx, u.Prefix+userId, "0", noTTL)
	_ = pipe.Expire(ctx, u.Prefix+userId, u.Expiry)
	verCmd := pipe.Get(ctx, u.Prefix+userId)
	_, err := pipe.Exec(ctx)

	if err != nil {
		return "", err
	}

	return verCmd.Val(), nil
}

func (u *UserModel) UpdateVersion(ctx context.Context, userId string) (string, error) {
	pipe := u.Redis.TxPipeline()
	verCmd := pipe.Incr(ctx, u.Prefix+userId)
	_ = pipe.Expire(ctx, u.Prefix+userId, u.Expiry)
	_, err := pipe.Exec(ctx)

	if err != nil {
		return "", err
	}
	ver := strconv.FormatInt(verCmd.Val(), 10)
	return ver, nil
}

package auth

import "time"

type UserKey struct {
	ID                 string   `json:"id"`
	Address            string   `json:"address"`
	PublicKey          string   `json:"public_key"`
	EphemeralPublicKey string   `json:"ephemeral_public_key"`
	DeviceId           string   `json:"device_id"`
	Permissions        []string `json:"permissions"`
	ExpiresAtSecs      int64    `json:"expires_at_secs"`
}

type UserPermissions struct {
	Address     string   `json:"-"`
	Permissions []string `json:"permissions"`
}

func (u *UserKey) GetSigningKey() string {
	if u.EphemeralPublicKey != "" {
		return u.EphemeralPublicKey
	}
	return u.PublicKey
}

func (u *UserKey) isExpired() bool {
	var zero int64
	if u.ExpiresAtSecs == zero {
		return false
	}
	now := time.Now().Unix()
	return u.ExpiresAtSecs < now
}

type SignInOutput struct {
	Token string `json:"token"`
}

type SignInput struct {
	Timestamp string `json:"timestamp"`
	DeviceId  string `json:"device_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`

	ExpiresAt                   int64  `json:"exp_date_secs"`
	EphemeralPublicKey          string `json:"epk"`
	EphemeralPublicKeySignature string `json:"epk_signature"`
}

package base_auth

import (
	"github.com/techpro-studio/gohttplib/validator"
	"net/http"
)

func ParseInput(r *http.Request) (*SignInput, error) {
	const kPublicKey = "public_key"
	const kEphemeralPublicKey = "epk"
	const kEphemeralPublicKeySignature = "epk_signature"

	const kTimestamp = "timestamp"
	const kSignature = "signature"
	const kDeviceId = "device_id"
	const kExpiresAt = "expires_at_secs"

	body, err := validator.GetValidatedBody(r, validator.VMap{
		kPublicKey:                   validator.RequiredStringValidators(kPublicKey),
		kTimestamp:                   validator.RequiredStringValidators(kTimestamp),
		kSignature:                   validator.RequiredStringValidators(kSignature),
		kDeviceId:                    validator.RequiredStringValidators(kDeviceId),
		kEphemeralPublicKey:          validator.RequiredStringValidators(kEphemeralPublicKey),
		kEphemeralPublicKeySignature: validator.RequiredStringValidators(kEphemeralPublicKeySignature),
		kExpiresAt:                   validator.RequiredFloatValidators(kExpiresAt),
	})
	if err != nil {
		return nil, err
	}
	return &SignInput{
		EphemeralPublicKey:          body[kEphemeralPublicKey].(string),
		PublicKey:                   body[kPublicKey].(string),
		EphemeralPublicKeySignature: body[kEphemeralPublicKeySignature].(string),
		ExpiresAt:                   int64(body[kExpiresAt].(float64)),
		Signature:                   body[kSignature].(string),
		Timestamp:                   body[kTimestamp].(string),
		DeviceId:                    body[kDeviceId].(string),
	}, nil
}

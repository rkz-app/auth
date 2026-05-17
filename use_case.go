package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/golang-jwt/jwt/v5"
	"github.com/techpro-studio/gohttplib"
	"time"
)

type UseCase struct {
	repository            Repository
	permissionsRepository PermissionsRepository
	addressGenerator      AddressGenerator
	allowMultipleKeys     bool
	sharedSecret          string
	jwtIssuer             string
}

func NewUseCase(repository Repository, permissionsRepository PermissionsRepository, addressGenerator AddressGenerator, allowMultipleKeys bool, sharedSecret string, jwtIssuer string) *UseCase {
	return &UseCase{repository: repository, permissionsRepository: permissionsRepository, addressGenerator: addressGenerator, allowMultipleKeys: allowMultipleKeys, sharedSecret: sharedSecret, jwtIssuer: jwtIssuer}
}

func (uc *UseCase) SignInWithPublicKeyAddressExpires(ctx context.Context, publicKey string, ephemeralPublicKey string, address string, deviceId string, expiresAt int64) (*SignInOutput, error) {
	if !uc.allowMultipleKeys {
		err := uc.repository.DeleteUserKeys(ctx, address)
		if err != nil {
			return nil, err
		}
	}

	userKey, err := uc.repository.CreateUserKey(ctx, publicKey, ephemeralPublicKey, address, deviceId, expiresAt)

	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{
		"iss": uc.jwtIssuer,
		"aud": userKey.ID,
		"sub": fmt.Sprintf("%s.%s", userKey.Address, userKey.DeviceId),
		"iat": time.Now().Unix(),
	}
	var zero int64
	if expiresAt != zero {
		claims["exp"] = expiresAt
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenObj.SignedString([]byte(uc.sharedSecret))
	if err != nil {
		return nil, err
	}
	return &SignInOutput{Token: token}, nil
}

func (uc *UseCase) GetUserKeyFromToken(ctx context.Context, token string) (*UserKey, error) {
	tokenObj, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(uc.sharedSecret), nil
	})

	if err != nil {
		return nil, err
	}
	claims, ok := tokenObj.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token")
	}
	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, err
	}
	if issuer != uc.jwtIssuer {
		return nil, fmt.Errorf("invalid token")
	}

	userKey, err := uc.repository.GetUserKey(ctx, claims["aud"].(string))
	if err != nil {
		return nil, err
	}

	return userKey, nil
}

func (uc *UseCase) RevokeUserKey(ctx context.Context, currentUserKey *UserKey, key string) error {
	if currentUserKey.ID != key {
		userKey, err := uc.repository.GetUserKey(ctx, key)
		if err != nil {
			return err
		}
		if userKey == nil {
			return gohttplib.HTTP404(key)
		}
		if userKey.Address != currentUserKey.Address {
			return gohttplib.HTTP403("Permission denied. You are not authorized to access this resource")
		}
	}
	return uc.repository.DeleteUserKey(ctx, key)
}

func (uc *UseCase) VerifySignInput(input *SignInput) (*string, error) {
	signerKey := input.PublicKey
	signatureBytes, err := hex.DecodeString(input.EphemeralPublicKeySignature)
	if err != nil {
		return nil, gohttplib.HTTP400("when epk provided, epk_signature must be hex")
	}
	ephemeralPublicKeyBytes, err := hex.DecodeString(input.EphemeralPublicKey)
	if err != nil {
		return nil, gohttplib.HTTP400("when epk provided, epk must be hex")
	}
	rootKeyBytes, err := hex.DecodeString(input.PublicKey)
	if err != nil {
		return nil, gohttplib.HTTP400("when epk provided, public_key must be hex")
	}
	var verified = false
	if len(rootKeyBytes) == ed25519.PublicKeySize {
		verified = ed25519.Verify(rootKeyBytes, ephemeralPublicKeyBytes, signatureBytes)
	} else if len(rootKeyBytes) == mldsa65.PublicKeySize {
		var mldsaKey mldsa65.PublicKey
		err = mldsaKey.UnmarshalBinary(rootKeyBytes)
		if err != nil {
			return nil, gohttplib.HTTP400("when epk provided non length 32, epk must be hex")
		}
	} else {
		return nil, gohttplib.HTTP400("Unknown signature")
	}
	if !verified {
		return nil, gohttplib.HTTP400("when epk provided, epk_signature must be signed with public key")
	}
	signerKey = input.EphemeralPublicKey
	publicKey, err := hex.DecodeString(signerKey)
	if err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(input.Signature)
	if err != nil {
		return nil, err
	}
	verified = ed25519.Verify(publicKey, []byte(input.Timestamp+input.DeviceId), signature)
	if !verified {
		return nil, gohttplib.HTTP403("Signature verification failed")
	}
	address, err := uc.GenerateAddressFromPublicKey(input.PublicKey)
	if err != nil {
		return nil, err
	}
	return &address, nil
}

func (uc *UseCase) GetUserKey(ctx context.Context, address string) (*UserKey, error) {
	userKeys, err := uc.repository.GetUserKeys(ctx, address)
	if err != nil {
		return nil, err
	}
	if len(userKeys) != 1 {
		return nil, gohttplib.HTTP404("User has no keys")
	}
	return userKeys[0], nil
}

func (uc *UseCase) GenerateAddressFromPublicKey(publicKey string) (string, error) {
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", err
	}
	return uc.addressGenerator.GenerateAddressFromPublicKey(publicKeyBytes)
}

func (uc *UseCase) GetUserPermissions(ctx context.Context, userKey *UserKey) (*UserPermissions, error) {
	return uc.permissionsRepository.GetPermissions(ctx, userKey.Address)
}

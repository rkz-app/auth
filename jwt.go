package auth

import "github.com/golang-jwt/jwt/v5"

type JWTConfig struct {
	signingMethod   jwt.SigningMethod
	signingKey      any
	verificationKey any
	issuer          string
	blinder         string
}

func (config JWTConfig) SigningMethod() jwt.SigningMethod {
	return config.signingMethod
}

func (config JWTConfig) SigningKey() any {
	return config.signingKey
}

func (config JWTConfig) VerificationKey() any {
	return config.verificationKey
}

func (config JWTConfig) Blinder() string {
	return config.blinder
}

func (config JWTConfig) Copy() JWTConfig {
	return JWTConfig{
		signingMethod:   config.signingMethod,
		signingKey:      config.signingKey,
		verificationKey: config.verificationKey,
		blinder:         config.blinder,
	}
}

func NewJWTConfig(signingMethod jwt.SigningMethod, signingKey any, verificationKey any, issuer string, blinder string) *JWTConfig {
	return &JWTConfig{signingMethod: signingMethod, signingKey: signingKey, verificationKey: verificationKey, issuer: issuer, blinder: blinder}
}

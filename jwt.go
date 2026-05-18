package auth

import "github.com/golang-jwt/jwt/v5"

type Method struct {
	signingMethod   jwt.SigningMethod
	signingKey      any
	verificationKey any
}

func NewMethod(signingMethod jwt.SigningMethod, signingKey any, verificationKey any) Method {
	return Method{signingMethod: signingMethod, signingKey: signingKey, verificationKey: verificationKey}
}

type JWTConfig struct {
	mainMethod   Method
	legacyMethod *Method
	issuer       string
	blinder      string
}

func NewJWTConfig(mainMethod Method, legacyMethod *Method, issuer string, blinder string) *JWTConfig {
	return &JWTConfig{mainMethod: mainMethod, legacyMethod: legacyMethod, issuer: issuer, blinder: blinder}
}

func (config JWTConfig) SigningMethod() jwt.SigningMethod {
	return config.mainMethod.signingMethod
}

func (config JWTConfig) SigningKey() any {
	return config.mainMethod.signingKey
}

func (config JWTConfig) VerificationKey() any {
	return config.mainMethod.verificationKey
}

func (config JWTConfig) Blinder() string {
	return config.blinder
}

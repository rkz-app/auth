package auth

import (
	"net/http"
)

type RequestVerifier interface {
	VerifyRequest(r *http.Request, key *UserKey) bool
}

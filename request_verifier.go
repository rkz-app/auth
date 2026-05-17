package base_auth

import (
	"net/http"
)

type RequestVerifier interface {
	VerifyRequest(r *http.Request, key *UserKey) bool
}

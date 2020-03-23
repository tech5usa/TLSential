package api

import (
	"github.com/ImageWare/TLSential/auth"
	"github.com/ImageWare/TLSential/user"

	rbac "github.com/mikespook/gorbac"
)

// ServerContext keeps context for the whole API.
type ServerContext struct {
	Version string
	us      user.Service
	*auth.JWTSecret
	*rbac.RBAC
}

func NewServerContext(version string, us user.Service, secret *auth.JWTSecret, rbac *rbac.RBAC) *ServerContext {
	return &ServerContext{version, us, secret, rbac}
}

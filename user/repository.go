package user

import (
	"github.com/ImageWare/TLSential/model"
)

// Repository provides an interface for how to store and retrieve User objects
// from a persistence engine.
type Repository interface {
	GetAllUsers() ([]*model.User, error)
	GetUser(name string) (*model.User, error)
	SaveUser(u *model.User) error
	DeleteUser(name string) error
	DeleteAllUsers() error
}

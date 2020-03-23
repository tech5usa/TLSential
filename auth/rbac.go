package auth

import (
	"github.com/mikespook/gorbac"
)

// Create separate read and write permissions
var (
	PermHPFRead  = gorbac.NewStdPermission("hpf_read")
	PermHPFWrite = gorbac.NewStdPermission("hpf_write")

	PermUserRead  = gorbac.NewStdPermission("user_read")
	PermUserWrite = gorbac.NewStdPermission("user_write")

	// Just for hpfeeds
	RoleHPFReader = "hpf_reader"
	RoleHPFAdmin  = "hpf_admin"

	// Just for user management
	RoleUserReader = "user_reader"
	RoleUserAdmin  = "user_admin"

	// Can control both
	RoleSuperAdmin = "super_admin"
)

// rbac returns a new instance of gorbac.RBAC for Role-Based Access Controls.
func InitRBAC() *gorbac.RBAC {
	r := gorbac.New()

	// Basic READ rights for HPFeeds
	rhpfr := gorbac.NewStdRole(RoleHPFReader)
	rhpfr.Assign(PermHPFRead)
	r.Add(rhpfr)

	// Read and write for HPFeeds
	rhpfa := gorbac.NewStdRole(RoleHPFAdmin)
	rhpfa.Assign(PermHPFRead)
	rhpfa.Assign(PermHPFWrite)
	r.Add(rhpfa)

	// Basic READ for HPFBroker users
	rur := gorbac.NewStdRole(RoleUserReader)
	rur.Assign(PermUserRead)
	r.Add(rur)

	// Read and write for HPFBroker users
	rua := gorbac.NewStdRole(RoleUserAdmin)
	rua.Assign(PermUserRead)
	rua.Assign(PermUserWrite)
	r.Add(rua)

	// Super admin inherits both HPF Admin and User Admin
	rsa := gorbac.NewStdRole(RoleSuperAdmin)
	r.Add(rsa)
	r.SetParents(RoleSuperAdmin, []string{RoleUserAdmin, RoleHPFAdmin})

	return r
}

// ValidRole takes a string and compares it to a list of valid rules. Returns
// true if there is a match.
func ValidRole(r string) bool {
	roles := []string{
		RoleHPFReader,
		RoleHPFAdmin,
		RoleUserReader,
		RoleUserAdmin,
		RoleSuperAdmin,
	}

	for _, role := range roles {
		if r == role {
			return true
		}
	}

	return false
}

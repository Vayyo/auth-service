package domain

type Role struct {
	ID          uint
	Name        string
	Description string
	Permissions []Permission
}

type Permission struct {
	ID          uint
	Name        string
	Description string
}

type RolePermission struct {
	RoleID     string
	Permission string
}

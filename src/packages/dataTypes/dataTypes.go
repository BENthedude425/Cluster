package dataTypes

type UserInfo struct {
	UserID   int
	Username string
	Password string

	AuthToken string
}

type UserInterface interface {
}

package dataTypes

type DBDataType interface {
	UserInfo | ChatRoomInfo
}

type UserInfo struct {
	UserID   int
	Username string
	Password string

	AuthToken string
}

// Example
type ChatRoomInfo struct{}

type UserInterface interface {
}

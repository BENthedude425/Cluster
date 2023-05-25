package dataTypes

type DBDataType interface {
	UserInfo | Chat | TableEntry
}

type TableEntry struct {
	ID   int
	Data any
}

type UserInfo struct {
	Username     string
	Password     string
	ProfilePicID string

	UserData  UserData
	AuthToken string
}

type UserData struct {
	FriendIDs         []int
	FriendRequestsIDs []FriendRequest
	Chats             []Chat
}

type FriendRequest struct {
	InitiatorID int
	RecieverID  int
}

type Message struct {
	Sender  string
	Message string
	Time    string
}

type Chat struct {
	ChatName   string
	Admins     []int
	Recipients []int
	Messages   []Message
}

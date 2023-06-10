package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"os"
	"packages/dataTypes"
	"packages/dbms"
	"strconv"
	"strings"
)

const DATAFILESPATH = "DB/"
const WEBSERVERPORT = "8080"
const CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

var DebugMode = true
var PrintServerInfo = true

var EssentialFiles = map[string]string{
	"USERSFILE": "UsersData.Json", // Stores User Data
	"CHATSFILE": "Chats.Json",     // Stores all chats
	"DEBUGFILE": "Debug.txt",      // Checks to see debug setting
}

var EssentialDirectories = map[string]string{
	"USERPROFILEPICS": "Static/ProfilePics",
}

func ReturnSuccessValue(Success bool, Reason string) []byte {
	// Create the success message
	var ResponseData = [][]string{
		{"success", strconv.FormatBool(Success), Reason},
	}

	ResponseDataBytes, err := json.Marshal(ResponseData)
	LogErr(err)

	return ResponseDataBytes
}

func IfEmptyString(StringPointer *string, Text string) string {
	if *StringPointer == "" {
		*StringPointer = Text
	}

	return ""
}

// args: message, label, logtype, alwayslog, newline
func DebugLog(message string, label string, EXTRAPARAMS ...string) {
	logtype, _ := GetIndex(0, EXTRAPARAMS)
	alwayslog, _ := GetIndex(1, EXTRAPARAMS)
	newline, _ := GetIndex(2, EXTRAPARAMS)

	IfEmptyString(&logtype, "INFO")
	IfEmptyString(&alwayslog, "false")
	IfEmptyString(&newline, "true")

	// WhiteSpace const to make the log less crammed and easier to read
	whitespacenum := 25

	// Calcuate needed whitespaces
	neededwhitespace := whitespacenum - len(label)
	whitespace := " "

	// Add whitespace
	if neededwhitespace > 0 {
		for i := 0; i < neededwhitespace; i++ {
			whitespace += " "
		}
	}

	LogMessage := fmt.Sprintf("[%s]%s[%s]			%s", label, whitespace, strings.ToUpper(logtype), message)

	if newline == "true" {
		LogMessage += "\n"
	}

	if DebugMode || alwayslog == "true" {
		fmt.Print(LogMessage)
	}
}

func HashString(data string) [32]byte {
	return sha256.Sum256([]byte(data))
}

func CheckEssentialFiles() error {
	DebugLog("Checking FileSystem integrity", "CheckEssentialFiles", "checking")

	_, err := os.Stat(DATAFILESPATH)

	// Check the common data directory
	if os.IsNotExist(err) {
		DebugLog("Created new directory", "CheckEssentialFiles", "checking")
		err2 := os.Mkdir(DATAFILESPATH, os.ModeDir)
		if err2 != nil {
			return err2
		}
	}

	for DirectoryType, DirectoryName := range EssentialDirectories {
		DebugLog(fmt.Sprintf("Checking if %s exists under %s ...", DirectoryType, DirectoryName), "CheckEssentialFiles", "checking", "false", "false")
		_, err := os.Stat(DirectoryName)

		if os.IsNotExist(err) {
			fmt.Printf("[FAILED]\n")
			DebugLog(fmt.Sprintf("Creating %s ...", DirectoryName), "CheckEssentialFiles", "system", "false", "false")
			err2 := os.Mkdir(DirectoryName, os.ModeDir)

			if err2 != nil {
				fmt.Printf("[FAILED]\n")
				return err2
			}
		}

		fmt.Printf("[OK]\n")
	}

	// Check Each individual file
	for key, value := range EssentialFiles {
		FileName := value
		FullFilePath := GetFilePath(FileName)
		DebugLog(fmt.Sprintf("Checking for %s under %s ...", key, FullFilePath), "CheckEssentialFiles", "checking", "false", "false")
		_, err = os.Stat(FullFilePath)
		if os.IsNotExist(err) {
			fmt.Printf("[FAILED]\n")
			DebugLog(fmt.Sprintf("Creating %s ...", FullFilePath), "CheckEssentialFiles", "system", "false", "false")

			_, err = os.Create(FullFilePath)
			if err != nil {
				fmt.Printf("[FAILED]\n")
				return err
			}
			fmt.Printf("[OK]\n")
		} else {
			fmt.Printf("[OK]\n")
		}
	}

	return nil
}

func CheckUserExists(Username string, Password string) (bool, error) {
	DebugLog("Checking if user exists...", "CheckUserExists", "checking")
	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))
	LogErr(err)

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)
	LogErr(err)

	Password = strings.Trim(Password, " ")

	if err != nil {
		return false, err
	}

	for i := range Users {
		SelectedUser := Users[i]
		if SelectedUser.Username == Username && SelectedUser.Password == Password {
			return true, nil
		}
	}

	return false, nil
}

func CheckAuth(auth *http.Cookie, AuthCookieErr error) (bool, error) {
	if AuthCookieErr != nil {
		return false, AuthCookieErr
	}

	if len(auth.Value) == 0 {
		return false, nil
	}

	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))

	if err != nil {
		return false, err
	}

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)

	if err != nil {
		return false, err
	}

	if auth.Value == "NONE" {
		return false, nil
	}

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		if SelectedUser.AuthToken == auth.Value {
			return true, nil
		}
	}
	return false, nil
}

func GetFilePath(Filename string) string {
	return DATAFILESPATH + Filename
}

func GetIndex(x int, array []string) (string, error) {
	if len(array) == 0 {
		return "", nil
	}

	if len(array)-1 >= x {
		return array[x], nil
	}

	return "", fmt.Errorf("GetIndex: Could not get index")
}

func GetChatFromID(ChatID int) (dataTypes.Chat, error) {
	DebugLog(fmt.Sprintf("Searching for chat ID:%d", ChatID), "GetChatFromID")
	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["CHATSFILE"]))

	if err != nil {
		return dataTypes.Chat{}, err
	}

	Chats, err := dbms.FormatEntries[dataTypes.Chat](TableEntries)

	if len(Chats) == 0 {
		return dataTypes.Chat{}, fmt.Errorf("there are no chats to load")
	}

	for i := range TableEntries {
		SelectedChat := Chats[i]
		SelectedEntry := TableEntries[i]

		if SelectedEntry.ID == ChatID {
			return SelectedChat, err
		}
	}

	return dataTypes.Chat{}, fmt.Errorf("could not find chat from ID")
}

func GetUserFromID(ID int) (dataTypes.UserInfo, int, error) {
	DebugLog(fmt.Sprintf("Searching for userID: %d", ID), "GetUserFromID")
	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))

	if err != nil {
		return dataTypes.UserInfo{}, 0, err
	}

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)

	for UserIndex := range Users {
		SelectedUser := Users[UserIndex]
		SelectedEntry := TableEntries[UserIndex]

		if SelectedEntry.ID == ID {
			DebugLog(fmt.Sprintf("Found userID: %d", ID), "GetUserFromID")
			return SelectedUser, UserIndex, nil
		}
	}

	return dataTypes.UserInfo{}, 0, err
}

func GetUserFromFileWithUsername(username string) (dataTypes.UserInfo, error) {
	var User dataTypes.UserInfo
	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))

	if err != nil {
		return dataTypes.UserInfo{}, err
	}

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)

	if err != nil {
		return User, err
	}

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		if SelectedUser.Username == username {
			User = Users[i]
			return User, nil
		}
	}
	return User, fmt.Errorf("could not find user in database")
}

func GetUserFromFileWithAuth(authToken string) (dataTypes.UserInfo, error) {
	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))

	if err != nil {
		return dataTypes.UserInfo{}, err
	}

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)

	if err != nil {
		return dataTypes.UserInfo{}, err
	}

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		if SelectedUser.AuthToken == authToken {
			return SelectedUser, nil
		}
	}

	return dataTypes.UserInfo{}, fmt.Errorf("could not find user from auth: %s", authToken)
}

func ResetAuth(AuthToken *http.Cookie) error {
	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))

	if err != nil {
		return err
	}

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)

	if err != nil {
		return err
	}

	for UserIndex := range Users {
		SelectedUser := Users[UserIndex]
		if SelectedUser.AuthToken == AuthToken.Value {
			FoundUser := Users[UserIndex]
			FoundUser.AuthToken = ""
			Users[UserIndex] = FoundUser

			TableEntries[UserIndex].Data = Users[UserIndex]
			UserBytes, JsonErr := json.MarshalIndent(TableEntries, "", "	")

			if JsonErr != nil {
				return JsonErr
			}

			os.WriteFile(GetFilePath(EssentialFiles["USERSFILE"]), UserBytes, fs.ModeAppend)
		}
	}
	return nil
}

func GenerateNewAuthToken(username string) (string, error) {
	var NewAuthToken string

	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))

	if err != nil {
		return "", err
	}

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)

	if err != nil {
		return "nil", err
	}

	// Generate new auth token
	for i := 0; i < 32; i++ {
		NewAuthToken += string(CHARSET[rand.Intn(len(CHARSET))])
	}

	for EntryIndex := range TableEntries {
		SelectedUser := Users[EntryIndex]

		if SelectedUser.Username == username {
			SelectedUser.AuthToken = NewAuthToken

			TableEntries[EntryIndex].Data = SelectedUser
			UsersBytes, err := json.MarshalIndent(TableEntries, "", "	")

			if err != nil {
				return "", err
			}

			os.WriteFile(GetFilePath(EssentialFiles["USERSFILE"]), UsersBytes, fs.ModeAppend)
			DebugLog("Saved new auth token into the file", "GenerateNewAuthToken")
			return NewAuthToken, nil
		}
	}
	return "", nil
}

func AddUserToDatabase(NewUser dataTypes.UserInfo) error {
	HashedPass := HashString(NewUser.Password)
	NewUser.Password = fmt.Sprintf("%x", HashedPass)

	UserExists, err := CheckUserExists(NewUser.Username, NewUser.Password)

	if UserExists || err != nil {
		return err
	}

	var NewEntry dataTypes.TableEntry
	NewEntry.ID = dbms.GenerateNewID(GetFilePath(EssentialFiles["USERSFILE"]))
	NewEntry.Data = NewUser

	err = dbms.AppendDataToTable(GetFilePath(EssentialFiles["USERSFILE"]), NewEntry)

	if err != nil {
		return err
	}

	DebugLog("Added new user to the usersfile", "AddUserToDatabase", "SYSTEM", "true")
	return nil
}

func AddUserToChat(UserID int, ChatID int, Admin bool) error {
	var NewTableEntry dataTypes.TableEntry
	User, _, err := GetUserFromID(UserID)

	LogErr(err)

	UserData := User.UserData
	Chat, err := GetChatFromID(ChatID)
	LogErr(err)

	if err != nil {
		return err
	}

	NewUserDataChats := append(UserData.Chats, Chat)
	NewUserData := UserData
	NewUserData.Chats = NewUserDataChats

	err = EditUserData(UserID, NewUserData)

	if err != nil {
		return err
	}

	NewChatData := Chat
	if Admin {
		NewChatAdmins := Chat.Admins
		NewChatAdmins = append(NewChatAdmins, UserID)
		NewChatData.Admins = NewChatAdmins
	} else {
		NewChatRecipients := Chat.Recipients
		NewChatRecipients = append(NewChatRecipients, UserID)
		NewChatData.Recipients = NewChatRecipients
	}

	NewTableEntry.ID = dbms.GenerateNewID(GetFilePath(EssentialFiles["CHATSSFILE"]))
	err = dbms.AppendDataToTable(GetFilePath(EssentialFiles["CHATSFILE"]), NewTableEntry)

	return err
}

func SaveProfilePic(ProfilePicBytes []byte, FileExtension string) (string, error) {
	ProfilePicID := ""
	for i := 0; i < 20; i++ {
		ProfilePicID += fmt.Sprint(rand.Intn(9))
	}
	ProfilePicID += "." + FileExtension

	err := os.WriteFile(fmt.Sprintf("Static/ProfilePics/%s", ProfilePicID), ProfilePicBytes, os.ModeAppend)

	if err != nil {
		return "", err
	}

	DebugLog("Saving new profilepic", "SaveProfilePic")
	return ProfilePicID, nil
}

func EditUserData(UserID int, NewUserData dataTypes.UserData) error {
	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))
	LogErr(err)

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)
	LogErr(err)

	_, UserIndex, err := GetUserFromID(UserID)
	LogErr(err)

	if len(Users) == 0 {
		return fmt.Errorf("there were no users to edit in the database")
	}
	User := Users[UserIndex]

	User.UserData = NewUserData
	UsersBytes, err := json.Marshal(Users)

	os.WriteFile(GetFilePath(EssentialFiles["USERSFILE"]), UsersBytes, os.ModeAppend)
	return err
}

func LogErr(err error) {

	if err != nil {
		DebugLog(err.Error(), "LogErr", "error", "true")
		return
	}
}

func CreateFriendRequest(SenderUsername string, RecipientUsername string) error {
	var NewFriendRequest dataTypes.FriendRequest

	if len(RecipientUsername) == 0 {
		return fmt.Errorf("the username you entered was invalid")
	}

	if len(SenderUsername) == 0 {
		return fmt.Errorf("could not validate client username")
	}

	TableEntries, err := dbms.ReadTable(GetFilePath(EssentialFiles["USERSFILE"]))
	if err != nil {
		return err
	}

	Users, err := dbms.FormatEntries[dataTypes.UserInfo](TableEntries)

	if err != nil {
		return err
	}

	for EntryIndex := range TableEntries {
		SelectedUser := Users[EntryIndex]

		// Set the sender and reciever of the friend request
		if SelectedUser.Username == SenderUsername {
			NewFriendRequest.InitiatorID = TableEntries[EntryIndex].ID
		} else if SelectedUser.Username == RecipientUsername {
			NewFriendRequest.RecieverID = TableEntries[EntryIndex].ID
		}

	}

	if NewFriendRequest.RecieverID == 0 {
		return fmt.Errorf("could not find user")
	}

	// Attach friend request to each of the users in database
	for EntryIndex := range TableEntries {
		SelectedEntry := TableEntries[EntryIndex]
		SelectedUser := Users[EntryIndex]

		// If the selected user is part of the friend request attach the request to their profile
		if SelectedEntry.ID == NewFriendRequest.InitiatorID || SelectedEntry.ID == NewFriendRequest.RecieverID {
			for FriendRequestIndex := range SelectedUser.UserData.FriendRequestsIDs {
				SelectedFriendRequest := SelectedUser.UserData.FriendRequestsIDs[FriendRequestIndex]
				if SelectedFriendRequest == NewFriendRequest {
					return fmt.Errorf("friend request already exists")
				}
			}

			SelectedUser.UserData.FriendRequestsIDs = append(SelectedUser.UserData.FriendRequestsIDs, NewFriendRequest)
			TableEntries[EntryIndex].Data = SelectedUser
		}
	}

	TableEntriesBytes, err := json.MarshalIndent(TableEntries, "", "	")
	os.WriteFile(GetFilePath(EssentialFiles["USERSFILE"]), TableEntriesBytes, fs.ModeAppend)

	return err
}

// ------------------------------------------------------------------------------------------- //

func main() {
	fmt.Printf("---------------Pre-Initialisation---------------\n")
	err := CheckEssentialFiles()
	if err != nil {
		DebugLog("Failed to load database!		Shutting down.", "CheckEssentialFiles", "error")
		return
	}

	Test()

	DebugFileContents, err := dbms.ReadFile(GetFilePath(EssentialFiles["DEBUGFILE"]))

	if err != nil {
		fmt.Print(err)
	}

	if string(DebugFileContents) == "true" {
		DebugMode = true
	} else {
		DebugMode = false
	}

	DebugLog(fmt.Sprintf("Debugging mode is set to %t", DebugMode), "Main", "INFO", "true")

	fmt.Printf("---------------Initialised---------------\n")

	// Pass handlers
	http.HandleFunc("/api/", HandleApiRequest)
	http.HandleFunc("/", Servepage)

	DebugLog(fmt.Sprintf("Starting webserver on port: %s", WEBSERVERPORT), "Main")
	if err := http.ListenAndServe(fmt.Sprintf(":%s", WEBSERVERPORT), nil); err != nil {
		log.Fatal((err))
	}
}

func Test() {
	DebugLog("Test function initiated", "Test", "test")
	var User dataTypes.UserInfo
	User.Username = "BENthedude425"
	User.Password = "rawr"

	err := AddUserToDatabase(User)

	if err != nil {
		log.Fatal(err)
	}

	var User2 dataTypes.UserInfo
	User2.Username = "JU-freeze"
	User2.Password = "ju"

	err = AddUserToDatabase(User2)

	if err != nil {
		log.Fatal(err)
	}

	//newID := dbms.GenerateNewID(GetFilePath(EssentialFiles["USERSFILE"]))
	//var Chat dataTypes.Chat
	//Chat.ChatID = 0

	//err = AddUserToChat(0, 0, true)

	//if err != nil {
	//	log.Fatal(err)
	//}
}

func HandleApiRequest(Writer http.ResponseWriter, Request *http.Request) {
	if Request.Method == "POST" {

		AuthToken, AuthCookieErr := Request.Cookie("AuthToken")
		Request.ParseMultipartForm(Request.ContentLength)

		ApiFunc := strings.Split(Request.RequestURI, "/api/")[1]
		DebugLog(fmt.Sprintf("Incoming post request via the API  %s", Request.RequestURI), "HandleApiRequest")
		switch ApiFunc {
		case "login":
			Username := Request.PostFormValue("username")
			Password := Request.PostFormValue("password")
			HashedPassword := fmt.Sprintf("%x", sha256.Sum256([]byte(Password)))

			LoginSuccess, err := CheckUserExists(Username, HashedPassword)

			DebugLog(fmt.Sprintf("incoming login request: %s %s", Username, Password), "MAIN")
			LogErr(err)
			if err != nil {
				return
			}

			// Check Username and password against database
			if LoginSuccess {
				DebugLog("User successfully logged in!", "HandleApiRequest")
				// generate a new auth token for the user and then send it back to be stored in cookies
				NewAuthToken, err := GenerateNewAuthToken(Username)
				LogErr(err)

				var ResponseData = [][]string{
					{"Success", "true"},
					{"AuthToken", NewAuthToken},
					{"Redirect", "/mainpage.html"},
				}

				Writer.Header().Set("Content-Type", "application/json")
				json.NewEncoder(Writer).Encode(ResponseData)
			} else {

				Writer.Header().Set("Content-Type", "application/json")
				Writer.Write(ReturnSuccessValue(false, "FAILED"))
				return
			}
		case "create":
			Username := Request.FormValue("username")
			Password := Request.FormValue("password")
			ProfilePic, ProfilePicHeader, err := Request.FormFile("profile-pic")
			LogErr(err)

			User, _ := GetUserFromFileWithUsername(Username)

			//Check if the returned user is blank
			if User.Username == Username {
				DebugLog("Attempted account creation with an existing user", "HandleApiRequest")
				Writer.Write(ReturnSuccessValue(false, "Attempted account creation with an existing user"))
				return
			}

			ProfilePicBytes := bytes.NewBuffer(nil)
			_, err = io.Copy(ProfilePicBytes, ProfilePic)
			LogErr(err)

			ProfilePicID, err := SaveProfilePic(ProfilePicBytes.Bytes(), strings.Split(ProfilePicHeader.Filename, ".")[1])
			LogErr(err)

			NewUser := dataTypes.UserInfo{
				Username:     Username,
				Password:     Password,
				ProfilePicID: ProfilePicID,
			}

			err = AddUserToDatabase(NewUser)
			LogErr(err)
		case "logout":
			ResetAuth(AuthToken)

			ResponseDataBytes, err := json.Marshal(ReturnSuccessValue(true, "OK"))

			LogErr(err)

			Writer.Write(ResponseDataBytes)
			return
		case "FriendRequest":
			RecipientUsername := Request.PostFormValue("RecipientUsername")

			AuthPassed, CheckAuthErr := CheckAuth(AuthToken, AuthCookieErr)
			LogErr(CheckAuthErr)

			if AuthPassed {
				User, err := GetUserFromFileWithAuth(AuthToken.Value)
				if err != nil {
					fmt.Print(err)
					return
				}

				DebugLog("Trying to create friend request", "HandleAPIReqest")
				FriendReqErr := CreateFriendRequest(User.Username, RecipientUsername)
				LogErr(FriendReqErr)

				if FriendReqErr == nil {
					Writer.Write(ReturnSuccessValue(true, "OK"))
				} else {
					Writer.Write(ReturnSuccessValue(false, FriendReqErr.Error()))
				}

			}
		case "get/friends-list":
			var ResponseData [][]string
			User, err := GetUserFromFileWithAuth(AuthToken.Value)
			LogErr(err)

			UsersFriendsIDs := User.UserData.FriendIDs

			for FriendIndex := range UsersFriendsIDs {
				SelectedFriend := UsersFriendsIDs[FriendIndex]
				User, _, err := GetUserFromID(SelectedFriend)
				LogErr(err)

				Data := []string{User.Username, fmt.Sprintf("ProfilePics/%s", User.ProfilePicID)}

				ResponseData = append(ResponseData, Data)
			}

			ResponseDataBytes, err := json.Marshal(ResponseData)
			LogErr(err)

			// create a unique id
			// {username, pfp_url}

			Writer.Write(ResponseDataBytes)
		default:
			Writer.Write([]byte("There was an error with your request"))
		}
	} else {
		fmt.Fprintf(Writer, "Method unsupported on this API")
	}
}

func Servepage(Writer http.ResponseWriter, Request *http.Request) {
	if PrintServerInfo {
		DebugLog(fmt.Sprintf("[%s] Request Recieved from %s for %s", Request.Method, Request.RemoteAddr, Request.RequestURI), "Servepage")
	}

	AuthToken, AuthCookieErr := Request.Cookie("AuthToken")

	AuthPassed, err := CheckAuth(AuthToken, AuthCookieErr)

	if err != nil {
		if err != http.ErrNoCookie {
			LogErr(err)
		}
	}

	if Request.RequestURI == "/" {
		Request.RequestURI = "/index.html"
	}

	if Request.RequestURI == "/index.html" || Request.RequestURI == "/create.html" || Request.RequestURI == "/test.html" {
		if AuthPassed {
			// If the client has a correct auth-token
			http.Redirect(Writer, Request, "/mainpage.html", http.StatusMovedPermanently)
			return
		}

	} else if strings.HasSuffix(Request.RequestURI, ".html") {
		if !AuthPassed {
			http.Redirect(Writer, Request, "/index.html", http.StatusMovedPermanently)
			return
		}
	}

	http.ServeFile(Writer, Request, fmt.Sprintf("static/%s", Request.RequestURI[1:]))
}

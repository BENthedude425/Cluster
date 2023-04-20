package main

import (
	"Go-Chat-App/src/packages/dataTypes"
	"Go-Chat-App/src/packages/dbms"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
)

const DATAFILESPATH = "data/"
const WEBSERVERPORT = "8080"
const CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

var DebugMode = true

var EssentialFiles = map[string]string{
	"USERSFILE":    "Users.Json",          // Stores User Credentials
	"USERDATAFILE": "StoredUserData.Json", // Stores User Data
	"CHATSFILE":    "Chats.Json",          // Stores all chats
	"DEBUGFILE":    "Debug.txt",           // Checks to see debug setting
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
	ChatID     string
	ChatName   string
	Recipients []int
	Messages   []Message
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

func DebugLog(message string, label string, EXTRAPARAMS ...string) {
	logtype, _ := GetIndex(0, EXTRAPARAMS)

	// WhiteSpace const to make the log less crammed and easier to read
	whitespacenum := 25

	alwayslog, _ := GetIndex(1, EXTRAPARAMS)

	if logtype == "" {
		logtype = "INFO"
	}

	if alwayslog == "" {
		alwayslog = "false"
	}

	// Calcuate needed whitespace

	neededwhitespace := whitespacenum - len(label)
	whitespace := " "
	// Add whitespace
	if neededwhitespace > 0 {
		for i := 0; i < neededwhitespace; i++ {
			whitespace += " "
		}
	}

	if DebugMode || alwayslog == "true" {
		fmt.Printf("[%s]%s[%s]			%s\n", label, whitespace, strings.ToUpper(logtype), message)
	}
}

func CheckUserExists(Username string, Password string) (bool, error) {
	Users, err := ReadUserTable()

	Password = strings.Trim(Password, " ")

	if err != nil {
		return false, err
	}

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]

		if SelectedUser.Username == Username && SelectedUser.Password == Password {
			DebugLog(fmt.Sprintf("Log in successful for: %s", Username), "CheckUserExists")
			return true, nil
		}
	}

	return false, nil
}

func FindUserFromID(ID int) (dataTypes.UserInfo, error) {
	DebugLog(fmt.Sprintf("Searching for userID: %d", ID), "FindUserFromID")
	Users, err := ReadUserTable()

	for UserIndex := range Users {
		User := Users[UserIndex]
		if User.UserID == ID {
			DebugLog(fmt.Sprintf("Found userID: %d", ID), "FindUserFromID")
			return User, nil
		}
	}

	return dataTypes.UserInfo{}, err
}

func HashString(data string) [32]byte {
	return sha256.Sum256([]byte(data))
}

func CheckAuth(auth *http.Cookie, AuthCookieErr error) (bool, error) {
	if AuthCookieErr != nil {
		return false, fmt.Errorf("Failed to recieve the AuthToken cookie")
	}

	if len(auth.Value) == 0 {
		return false, nil
	}

	Users, err := ReadUserTable()

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

func GetUserFromFileWithUsername(username string) (dataTypes.UserInfo, error) {
	var User dataTypes.UserInfo
	Users, err := ReadUserTable()

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
	return User, fmt.Errorf("Could not find user in database")
}

func GetUserFromFileWithAuth(authToken string) (dataTypes.UserInfo, error) {
	Users, err := ReadUserTable()
	if err != nil {
		return dataTypes.UserInfo{}, err
	}

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		if SelectedUser.AuthToken == authToken {
			return SelectedUser, nil
		}
	}

	return dataTypes.UserInfo{}, fmt.Errorf("Could not find user from auth: %s", authToken)
}

func GenerateNewAuthToken(username string) (string, error) {
	var NewAuthToken string

	Users, err := ReadUserTable()

	if err != nil {
		return "nil", err
	}

	// Generate new auth token
	for i := 0; i < 32; i++ {
		NewAuthToken += string(CHARSET[rand.Intn(len(CHARSET))])
	}

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		if SelectedUser.Username == username {
			Users[i].AuthToken = NewAuthToken

			UsersBytes, err := json.MarshalIndent(Users, "", "	")

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

func GenerateNewUserIDFromFile() int {
	Users, err := ReadUserTable()
	NewID := 0
	FoundID := true
	if err != nil {
		log.Fatal(err)
		return 0
	}

	if len(Users) == 0 {
		return NewID
	}

	DebugLog(fmt.Sprintf("Searching for new ID for new user..."), "GenerateNewUserIDFromFile", "SEARCHING")
	for {
		FoundID = true
		NewID += 1
		for i := 0; i < len(Users); i++ {
			SelectedUser := Users[i]

			if SelectedUser.UserID == NewID {
				FoundID = false
				break
			}
		}

		if FoundID {
			DebugLog(fmt.Sprintf("Found New user ID: %d", NewID), "GenerateNewUserIDFromFile", "Sucess")
			return NewID
		}
	}
}

func GetFilePath(Filename string) string {
	return DATAFILESPATH + Filename
}

func AddUserToDatabase(User dataTypes.UserInfo) error {
	UsernameExists := false
	Users, err := ReadUserTable()

	if err != nil {
		return err
	}

	HashedPass := HashString(User.Password)
	User.Password = fmt.Sprintf("%x", HashedPass)

	// Check that there is not an existing user with the same username
	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		if SelectedUser.Username == User.Username {
			UsernameExists = true
			break
		}
	}

	if UsernameExists {
		return fmt.Errorf("Username already exists")
	}

	NewUsersFile := append(Users, User)

	FileContentsBytes, err := json.MarshalIndent(NewUsersFile, "", "	")

	if err != nil {
		return err
	}

	err = os.WriteFile(GetFilePath(EssentialFiles["USERSFILE"]), FileContentsBytes, fs.ModeAppend)

	if err != nil {
		return err
	}

	DebugLog("Added new user to the usersfile", "AddUserToDatabase", "SYSTEM", "true")
	return nil
}

func ReadUserTable() ([]dataTypes.UserInfo, error) {
	var Users []dataTypes.UserInfo
	FilePath := GetFilePath(EssentialFiles["USERSFILE"])
	UserBytes, err := dbms.ReadTable(FilePath)

	if err != nil {
		DebugLog("Failed to read the users table", "ReadUserTable", "error")
		return []dataTypes.UserInfo{}, err
	}

	// Convert file contents into object
	err = json.Unmarshal(UserBytes, &Users)
	if err != nil {
		DebugLog("Failed to load users table data into object notation", "ReadUserTable", "error")
		return []dataTypes.UserInfo{}, err
	}

	DebugLog(fmt.Sprintf("Loaded: %d Users From: %s", len(Users), EssentialFiles["USERSFILE"]), "ReadUserTable")
	return Users, nil
}

func LogErr(err error) {

	if err != nil {
		DebugLog(err.Error(), "Test", "error", "true")
		return
	}
}

func CreateFriendRequest(SenderUsername string, RecipientUsername string) error {

	return nil
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

	// Check Each individual file
	for key, value := range EssentialFiles {
		FileName := value
		FullFilePath := GetFilePath(FileName)
		DebugLog(fmt.Sprintf("Checking for %s under %s ...", key, FullFilePath), "CheckEssentialFiles", "checking")
		_, err = os.Stat(FullFilePath)
		if os.IsNotExist(err) {
			DebugLog(fmt.Sprintf("Creating %s ...", FullFilePath), "CheckEssentialFiles", "checking")

			_, err = os.Create(FullFilePath)
			if err != nil {
				DebugLog("FAILED", "CheckEssentialFiles")
				return err
			}
			DebugLog("[OK]", "CheckEssentialFiles")
		}
	}

	return nil
}

func ReadFile(FileName string) (string, error) {
	FullFilePath := GetFilePath(FileName)
	File, err := os.Open(FullFilePath)
	FileSystem, err := os.Stat(FullFilePath)
	FileSize := FileSystem.Size()
	FileBuffer := make([]byte, FileSize)

	_, err = File.Read(FileBuffer)
	File.Close()

	if err != nil {
		return "", err
	}

	return string(FileBuffer), nil
}

// ------------------------------------------------------------------------------------------- //

func main() {
	err := CheckEssentialFiles()
	if err != nil {
		DebugLog("Failed to laod database!		Shutting down.", "CheckEssentialFiles", "error")
		fmt.Printf("Failed to load database ;/\n%e\n\nShutting down.", err)
		return
	}

	Test()

	DebugFileContents, err := ReadFile(EssentialFiles["DEBUGFILE"])

	if err != nil {
		fmt.Print(err)
	}

	if DebugFileContents == "true" {
		DebugMode = true
	} else {
		DebugMode = false
	}

	DebugLog(fmt.Sprintf("Debugging mode is set to %t", DebugMode), "MAIN", "INFO", "true")

	fmt.Printf("---------------Initialised---------------\n")

	// Pass handlers
	http.HandleFunc("/api/", HandleApiRequest)
	http.HandleFunc("/", Servepage)

	fmt.Printf("Starting webserver on port %s\n", WEBSERVERPORT)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", WEBSERVERPORT), nil); err != nil {
		log.Fatal((err))
	}
}

func Test() {
	fmt.Println("Test")

	dbms.AppendDataToTable[dataTypes.UserInfo](GetFilePath(EssentialFiles["USERSFILE"]))
}

func HandleApiRequest(Writer http.ResponseWriter, Request *http.Request) {
	if Request.Method == "POST" {
		ApiFunc := strings.Split(Request.RequestURI, "/api/")[1]
		switch ApiFunc {
		case "login":
			Username := Request.PostFormValue("username")
			Password := Request.PostFormValue("password")
			HashedPassword := fmt.Sprintf("%x", sha256.Sum256([]byte(Password)))

			LoginSucess, err := CheckUserExists(Username, HashedPassword)

			if err != nil {
				return
			}

			// Check Username and password against database
			if LoginSucess {
				// generate a new auth token for the user and then send it back to be stored in cookies

				NewAuthToken, err := GenerateNewAuthToken(Username)
				LogErr(err)

				var ResponseData = [][]string{
					{"sucess", "true"},
					{"AuthToken", NewAuthToken},
					{"Redirect", "/mainpage.html"},
				}

				Writer.Header().Set("Content-Type", "application/json")
				json.NewEncoder(Writer).Encode(ResponseData)
			} else {

				var ResponseData = [][]string{
					{"sucess", "false"},
				}

				Writer.Header().Set("Content-Type", "application/json")
				json.NewEncoder(Writer).Encode(ResponseData)
				return
			}
		case "logout":
			AuthToken, AuthCookieErr := Request.Cookie("AuthToken")

			if AuthCookieErr != nil {
				return
			}

			Users, err := ReadUserTable()

			if err != nil {
				return
			}

			for UserIndex := range Users {
				if Users[UserIndex].AuthToken == AuthToken.Value {
					Users[UserIndex].AuthToken = ""
					UserBytes, JsonErr := json.MarshalIndent(Users, "", "	")
					if JsonErr != nil {
						return
					}
					os.WriteFile(GetFilePath(EssentialFiles["USERSFILE"]), UserBytes, fs.ModeAppend)
				}

			}

		case "FriendRequest":
			RecipientUsername := Request.PostFormValue("RecipientUsername")
			AuthToken, AuthCookieErr := Request.Cookie("AuthToken")

			AuthPassed, err := CheckAuth(AuthToken, AuthCookieErr)
			fmt.Print(err)

			if AuthPassed {
				User, err := GetUserFromFileWithAuth(AuthToken.Value)
				if err != nil {
					fmt.Print(err)
					return
				}

				CreateFriendRequest(User.Username, RecipientUsername)

			}

		default:
			Writer.Write([]byte("There was an error with your request"))
			break
		}
	} else {
		fmt.Fprintf(Writer, "Method unsupported on this API")
	}
}

func Servepage(Writer http.ResponseWriter, Request *http.Request) {
	fmt.Printf("[%s] Request Recieved from %s for %s \n", Request.Method, Request.RemoteAddr, Request.RequestURI)
	AuthToken, AuthCookieErr := Request.Cookie("AuthToken")

	AuthPassed, err := CheckAuth(AuthToken, AuthCookieErr)

	if err != nil {
		LogErr(err)
	}

	if Request.RequestURI == "/" {
		Request.RequestURI = "/index.html"
	}

	if Request.RequestURI == "/index.html" {
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

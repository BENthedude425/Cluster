package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"os"
	"packages/dbms"
	"strings"
)

const DataFilesPath = "data/"
const WebServerPort = "8080"

var DebugMode = true

var x = map[string]string{
	"S":    "cap letter",
	"asdf": "words",
}

var EssentialFiles = map[string]string{
	"USERSFILE":    "Users.Json",    // Stores User Credentials
	"USERDATAFILE": "UserData.Json", // Stores User Data
	"CHATSFILE":    "Chats.Json",    // Stores all chats
	"DEBUGFILE":    "Debug.txt",     // Checks to see debug setting
}

type UserData struct {
	UserID   int
	Username string
	Password string

	AuthToken string
}

type Message struct {
	Sender  string
	Message string
	time    string
}

type Chat struct {
	ChatID     string
	Recipients []string
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
	Users, err := ReadUserFile()

	Password = strings.Trim(Password, " ")

	if err != nil {
		return false, err
	}

	DebugLog("\n\n\n\n\n\n\n\n", "CheckUserExists", "")

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]

		if SelectedUser.Username == Username && SelectedUser.Password == Password {
			DebugLog(fmt.Sprintf("Found User! Logged in as %s", Username), "CheckUserExists")
			return true, nil
		}
	}

	return false, nil
}

func HashString(data string) [32]byte {
	return sha256.Sum256([]byte(data))
}

func CheckAuth(auth *http.Cookie, AuthCookieErr error) (bool, error) {
	if AuthCookieErr != nil {
		return false, fmt.Errorf("Failed to recieve the AuthToken cookie")
	}

	Users, err := ReadUserFile()

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

func GetUserFromFileWithUsername(username string) (UserData, error) {
	var User UserData
	Users, err := ReadUserFile()

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

func GetUserFromFileWithAuth(authToken string) (UserData, error) {
	Users, err := ReadUserFile()
	if err != nil {
		return UserData{}, err
	}

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		if SelectedUser.AuthToken == authToken {
			return SelectedUser, nil
		}
	}

	return UserData{}, fmt.Errorf("Could not find user from auth: %s", authToken)
}

func GenerateNewAuthToken(username string) (string, error) {
	var NewAuthToken string
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

	Users, err := ReadUserFile()

	if err != nil {
		return "nil", err
	}

	// Generate new auth token
	for i := 0; i < 32; i++ {
		NewAuthToken += string(charset[rand.Intn(len(charset))])
	}

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		fmt.Print(SelectedUser.Username)
		if SelectedUser.Username == username {
			Users[i].AuthToken = NewAuthToken

			BytesBuffer := new(bytes.Buffer)
			err = json.NewEncoder(BytesBuffer).Encode(Users)
			UsersBytes := BytesBuffer.Bytes()

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
	Users, err := ReadUserFile()
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
	return DataFilesPath + Filename
}

func AddUserToDatabase(User UserData) error {
	UsernameExists := false
	Users, err := ReadUserFile()

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

	FileContentsBytesBuffer := new(bytes.Buffer)
	err = json.NewEncoder(FileContentsBytesBuffer).Encode(NewUsersFile)
	FileContentsBytes := FileContentsBytesBuffer.Bytes()

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

func ReadUserFile() ([]UserData, error) {
	var Users []UserData
	FilePath := DataFilesPath + EssentialFiles["USERSFILE"]
	UserBytes, err := dbms.ReadTable(FilePath)

	if err != nil {
		return []UserData{}, err
	}

	// Convert file contents into object
	err = json.Unmarshal(UserBytes, &Users)
	if err != nil {
		return []UserData{}, err
	}

	DebugLog(fmt.Sprintf("Loaded: %d Users From: %s", len(Users), EssentialFiles["USERSFILE"]), "ReadUserFile")
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

	_, err := os.Stat(DataFilesPath)

	// Check the common data directory
	if os.IsNotExist(err) {
		DebugLog("Created new directory", "CheckEssentialFiles", "checking")
		err2 := os.Mkdir(DataFilesPath, os.ModeDir)
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
				fmt.Printf("[FAILED]\n")
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
		fmt.Printf("Failed to load database ;/\n%e\n\nShutting down.", err)
		return
	}

	ReadUserFile()

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

	fmt.Printf("Starting webserver on port %s\n", WebServerPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", WebServerPort), nil); err != nil {
		log.Fatal((err))
	}
}

func Test() {
	NewUser := UserData{GenerateNewUserIDFromFile(), "PENIS HEAD", "meow", ""}
	err := AddUserToDatabase(NewUser)

	if err != nil {
		LogErr(err)
	}

	NewUser = UserData{GenerateNewUserIDFromFile(), "BENthedude425", "rawr", ""}
	err = AddUserToDatabase(NewUser)
	if err != nil {
		LogErr(err)
	}
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

	if DebugMode {
		fmt.Print(err)
		fmt.Print("\n")
	}

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

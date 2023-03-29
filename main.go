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
	"strings"
)

const DataFilesPath = "data/"
const WebServerPort = "8080"

var DebugMode = true

var EssentialFiles = []string{
	"Users.Json",
	"Debug.txt",
}

type UserData struct {
	Username string
	Password string //change to pass hash later

	AuthToken string
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
	logtype, err := GetIndex(0, EXTRAPARAMS)
	LogErr(err)

	alwayslog, err := GetIndex(1, EXTRAPARAMS)
	LogErr(err)

	if logtype == "" {
		logtype = "INFO"
	}

	if alwayslog == "" {
		alwayslog = "false"
	}

	if DebugMode || alwayslog == "true" {
		fmt.Printf("[%s] [%s] %s\n", label, logtype, message)
	}
}

func CheckUserExists(Username string, Password string) (bool, error) {
	Users, err := ReadUserFile()

	if err != nil {
		return false, err
	}

	DebugLog("\n\n\n\n\n\n\n\n", "CheckUserExists", "")

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		DebugLog(fmt.Sprintf("%s : %s", SelectedUser.Password, Password), "CheckUserExists")

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

	for i := 0; i < len(Users); i++ {
		SelectedUser := Users[i]
		if SelectedUser.AuthToken == auth.Value {
			return true, nil
		}
	}
	return false, fmt.Errorf("Auth token is invalid")
}

func GetUserFromFile(username string) (UserData, error) {
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

			os.WriteFile(GetFilePath("Users.json"), UsersBytes, fs.ModeAppend)
			DebugLog("Saved new auth token into the file", "GenerateNewAuthToken")
			return NewAuthToken, nil
		}
	}
	return "", nil
}

func GetFilePath(Filename string) string {
	return DataFilesPath + Filename
}

func AddUserToDatabase(User UserData) error {
	Users, err := ReadUserFile()

	if err != nil {
		return err
	}

	HashedPass := HashString(User.Password)
	User.Password = fmt.Sprintf("%x", HashedPass)

	NewUsersFile := append(Users, User)

	DebugLog(fmt.Sprint("The user file now looks like: %s", NewUsersFile), "AddUserToDatabase")

	FileContentsBytesBuffer := new(bytes.Buffer)
	err = json.NewEncoder(FileContentsBytesBuffer).Encode(NewUsersFile)
	FileContentsBytes := FileContentsBytesBuffer.Bytes()

	if err != nil {
		return err
	}

	err = os.WriteFile(GetFilePath("Users.json"), FileContentsBytes, fs.ModeAppend)

	if err != nil {
		return err
	}

	DebugLog(fmt.Sprintf("new User file %s", string(FileContentsBytes)), "AddUserToDatabase")
	return nil
}

func ReadUserFile() ([]UserData, error) {
	FilePath := DataFilesPath + "Users.json"
	File, err := os.Open(FilePath)
	defer File.Close()

	if err != nil {
		return []UserData{}, err
	}

	FileSystem, err := os.Stat(FilePath)

	if err != nil {
		return []UserData{}, err
	}

	ContentsBuffer := make([]byte, FileSystem.Size())

	_, err = File.Read(ContentsBuffer)

	if err != nil {
		return []UserData{}, err
	}

	var FileContentsAsStruct []UserData
	if !json.Valid(ContentsBuffer) {
		DebugLog(fmt.Sprintf("File is corrupt or there is no data to load"), "ReadUserFile")
		return []UserData{}, nil
	}
	err = json.Unmarshal(ContentsBuffer, &FileContentsAsStruct)

	if err != nil {
		return []UserData{}, err
	}

	DebugLog(fmt.Sprintf("Loaded: %s\nFrom: %s", FileContentsAsStruct, string(ContentsBuffer)), "ReadUserFile")

	if err != nil {
		return []UserData{}, err
	}

	DebugLog(fmt.Sprintf("Found the File Contents of %s to be %s", FilePath, FileContentsAsStruct), "ReadUserFile")

	return FileContentsAsStruct, nil
}

func LogErr(err error) {

	if err != nil {
		fmt.Printf("%e\n", err)
		return
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

func HandleApiRequest(Writer http.ResponseWriter, Request *http.Request) {
	if Request.Method == "POST" {
		if Request.RequestURI == "/api/login" {
			Username := Request.PostFormValue("username")
			Password := Request.PostFormValue("password")
			HashedPassword := fmt.Sprintf("%x", sha256.Sum256([]byte(Password)))

			fmt.Printf("Incoming username and password: [%s,%s]\n", Username, Password)

			LoginSucess, err := CheckUserExists(Username, HashedPassword)

			if err != nil {
				return
			}

			// Check Username and password against database
			if LoginSucess {
				// generate a new auth token for the user and then send it back to be stored in cookies

				NewAuthToken, err := GenerateNewAuthToken("BENthedude425")
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
			}
		}
	} else {
		fmt.Fprintf(Writer, "Method unsupported on this API")
	}
}

func CheckEssentialFiles() error {
	DebugLog("Checking FileSystem integrity", "CheckEssentialFiles", "SYSTEM")

	_, err := os.Stat(DataFilesPath)

	// Check the common data directory
	if os.IsNotExist(err) {
		DebugLog("Created new directory", "CheckEssentialFiles", "SYSTEM")
		err2 := os.Mkdir(DataFilesPath, os.ModeDir)
		if err2 != nil {
			return err2
		}
	}

	// Check Each individual file
	for i := 0; i < len(EssentialFiles); i++ {
		FileName := EssentialFiles[i]
		FullFilePath := GetFilePath(FileName)
		DebugLog(fmt.Sprintf("Checking for %s ...", FullFilePath), "CheckEssentialFiles")
		_, err = os.Stat(FullFilePath)
		if os.IsNotExist(err) {
			fmt.Printf("[WARN]\n")
			fmt.Printf("[INfO] Creating %s...", FullFilePath)
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

func main() {
	err := CheckEssentialFiles()
	if err != nil {
		fmt.Printf("Failed to load database ;/\n%e\n\nShutting down.", err)
		return
	}

	DebugFileContents, err := ReadFile("Debug.txt")

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
	NewUser := UserData{"Benthedude425", "rawr", "123"}
	err := AddUserToDatabase(NewUser)

	//_, err := ReadUserFile("Users.txt")
	if err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
)

const DataFilesPath = "data/"
const WebServerPort = "8080"
const DebugMode = false

var EssentialFiles = []string{
	"Users.Json",
	"meow.txt",
	"sex.txt",
	"adf",
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
		logtype = "LOG"
	}

	if alwayslog == "" {
		alwayslog = "false"
	}

	if DebugMode || alwayslog == "true" {
		fmt.Printf("[%s] [%s] %s\n", label, logtype, message)
	}
}

func CheckAuth(auth *http.Cookie, authErr error) bool {
	if authErr != nil {
		return false
	}
	authvalue := auth.Value
	fakeauth := "1"
	return authvalue == fakeauth
}

func GenerateNewAuthToken(username string) string {
	return "NewAuthToken"
}

func GetFilePath(Filename string) string {
	return DataFilesPath + Filename
}

func AddUserToDatabase(User UserData) error {
	Users, err := ReadUserFile("Users.json")

	if err != nil {
		return err
	}

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

func ReadUserFile(Filename string) ([]UserData, error) {
	FilePath := DataFilesPath + Filename
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

	DebugLog(fmt.Sprintf("Loaded: %s\nFrom: %s", FileContentsAsStruct, string(ContentsBuffer)), "[ReadUserFile]")

	if err != nil {
		return []UserData{}, err
	}

	DebugLog(fmt.Sprintf("Found the File Contents of %s to be %s", Filename, FileContentsAsStruct), "[ReadUserFile]")

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
	AuthToken, AuthErr := Request.Cookie("AuthToken")
	AuthPassed := CheckAuth(AuthToken, AuthErr)

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

			fmt.Printf("Incoming username and password: [%s,%s]\n", Username, Password)

			// Check Username and password against database
			if Username == "BENthedude425" && Password == "rawr" {
				// generate a new auth token for the user and then send it back to be stored in cookies

				NewAuthToken := GenerateNewAuthToken("BENthedude425")

				fmt.Fprintf(Writer, "{{'sucess': true}, {'AuthToken':'%s'}", NewAuthToken)
				http.Redirect(Writer, Request, "/mainpage.html", 301)
			} else {
				http.Redirect(Writer, Request, "/index.html", 301)
			}
		}
	} else {
		fmt.Fprintf(Writer, "Method unsupported on this API")
	}
}

func CheckEssentialFiles() error {
	fmt.Printf("[SYSTEM] Checking FileSystem integrity\n")
	_, err := os.Stat(DataFilesPath)

	// Check the common data directory
	if os.IsNotExist(err) {
		fmt.Print("Created new data directory\n")
		err2 := os.Mkdir(DataFilesPath, os.ModeDir)
		if err2 != nil {
			return err2
		}
	}

	// Check Each individual file
	for i := 0; i < len(EssentialFiles); i++ {
		FileName := EssentialFiles[i]
		FullFilePath := GetFilePath(FileName)
		fmt.Printf("[INFO] Checking for %s ...", FullFilePath)
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

func main() {
	err := CheckEssentialFiles()
	if err != nil {
		fmt.Printf("Failed to load database ;/\n%e\n\nShutting down.", err)
		return
	}

	DebugLog(fmt.Sprintf("Debugging mode is set to %t", DebugMode), "MAIN", "INFO", "true")

	fmt.Printf("---------------Initialised---------------\n")
	Test()
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

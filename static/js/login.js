// Declare gobal variables
var UsernameEntry;
var PasswordEntry;
var Password2Entry;
var LoginForm;
var CreateForm;

function GetCredentialsForms(){
    UsernameEntry = document.getElementById("username");
    PasswordEntry = document.getElementById("password");
    Password2Entry = document.getElementById("password2");
    LoginForm = document.getElementById("Login-Form");
    CreateForm = document.getElementById("Create-Form");

    if (LoginForm != undefined){
        LoginForm.addEventListener("keydown", function(Event) {
            if (Event.code == "Enter") {
                Login();
            }
        })
    }
    
    if (CreateForm != undefined){
        CreateForm.addEventListener("keydown", function(Event){
            if (Event.code == "Enter"){
                CreateAccount();
            }
        })
    }
}

function CreateAccount(){
    FormChildren = CreateForm.children;
    
    var Password1;
    var Password2; 

    Password1 = PasswordEntry.value;
    Password2 = Password2Entry.value;

    if (Password1 != Password2){
        PasswordEntry.value = "";
        Password2Entry.value = "";
        alert("The two passwords entered do not match!\nPlease re-enter them");
        return;
    }

    API("post", "/create", CreateAccountCB, true, FormatForm("Create-Form"));
}

function CreateAccountCB(XHRrequest){
    SuccessResponse = JSON.parse(XHRrequest.responseText);

    if(SuccessResponse[0][1] == "false"){
        alert(SuccessResponse[0][2]);
    }
}

function Login(){
    var FormattedFormData = new FormData();
    FormattedFormData = FormatForm("Login-Form");
    
    API("post", "/login", LoginCB, true, FormattedFormData);
}

function LoginCB(XHRrequest){
    var ResponseDataRaw = XHRrequest.responseText;
    var ResponseDataSerialised = JSON.parse(ResponseDataRaw);
    var Success = ResponseDataSerialised[0][1];

    UsernameEntry.value = "";
    PasswordEntry.value = "";

    if(Success == "true"){
        var NewAuthToken = ResponseDataSerialised[1][1];
        var RedirectURL = ResponseDataSerialised[2][1];

        document.cookie = "AuthToken=" + NewAuthToken;
        window.location.href = RedirectURL;
    }else{
        alert("Authentification failed ;/\nPlease try again and make sure credentials are correct!");
    }
}

function LogOut(){
    API('post' ,'/logout', LogOutCB)
}

function LogOutCB(XHRrequest){
    document.cookie = "AuthToken=";
    window.location.href = "index.html";
}

function GetCookie(CookieName){
    var cookies = document.cookie;
    cookies = cookies.split(";")
    for(let i = 0; i < cookies.length; i++){
        cookie = cookies[i]
        SplitCookie = cookie.split("=")
        if (SplitCookie[0] == CookieName){
            return SplitCookie[1]
        }
    }
}

function SetCookie(CookieName, Value){
    var cookies = document.cookie;
    cookies = cookies.split(";")
    for(let i = 0; i < cookies.length; i++){
        cookie = cookies[i]
        SplitCookie = cookie.split("=")
        if (SplitCookie[0] == CookieName){
            document.cookie = CookieName + "=" + Value
        }
    } 
}
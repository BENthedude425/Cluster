// Declare gobal variables
var UsernameEntry;
var PasswordEntry;
var LoginForm;

function GetLoginForm(){
    UsernameEntry = document.getElementById("FormUsername");
    PasswordEntry = document.getElementById("FormPassword");
    LoginForm = document.getElementById("Login-Form");

    LoginForm.addEventListener("keydown", function (Event) {
        if (Event.code === "Enter") {
            Login();
        }
    })
}


function Login(){
    var UsernameValue = UsernameEntry.value;
    var PasswordValue = PasswordEntry.value;

    var FormData = "username=" + UsernameValue + "&password=" + PasswordValue;

    API("post", "/login", LoginCB, true, FormData)
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
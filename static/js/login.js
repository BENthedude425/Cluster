window.onload = function(){
    var Form = document.getElementById("Login-Form");
    Form.addEventListener("keydown", function (e) {
        if (e.code === "Enter") {  //checks whether the pressed key is "Enter"
            Login();
        }
    });

}

function Login(){
    var UsernameEntry = document.getElementById("FormUsername");
    var PasswordEntry = document.getElementById("FormPassword");

    var UsernameValue = UsernameEntry.value;
    var PasswordValue = PasswordEntry.value;

    var FormData = "username=" + UsernameValue + "&password=" + PasswordValue;

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/login");
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

    xhr.send(FormData);

    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            var ResponseDataRaw = xhr.responseText;
            console.log(ResponseDataRaw);

            UsernameEntry.value = "";
            PasswordEntry.value = "";

            var ResponseDataSerialised = JSON.parse(ResponseDataRaw);

            var Sucess = ResponseDataSerialised[0][1];

            if(Sucess == "true"){
                var NewAuthToken = ResponseDataSerialised[1][1];
                var RedirectURL = ResponseDataSerialised[2][1];

                document.cookie = "AuthToken=" + NewAuthToken;
                window.location.href = RedirectURL;
            }else{
                alert("Authentification failed ;/\nPlease try again and make sure credentials are correct!");
            }
        }
    }
}

function LogOut(){
    document.cookie = "AuthToken=NONE";
    document.location.href = "/index.html";
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
function CheckAuth(){
    var AuthToken = document.cookie("AuthToken");
    console.log("Found auth token to be:", AuthToken);

    var xhr = new XMLHttpRequest();
    xhr.open("get", "/api/login");
    xhr.send(AuthToken);

    if(xhr.readyState == 4){
        console.log(xhr.responseText);
    }
}
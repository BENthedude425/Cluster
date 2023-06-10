var FriendSearchBar;

function GetFriendSearchBar(){
    FriendSearchBar = document.getElementById("FriendSearchBar");

    FriendSearchBar.addEventListener("keydown", function(Event){
        if(Event.code == "Enter"){
            SendFriendRequest();
        }
    });
}

// API function to interact with the server and callback to a given function when the request is complete
async function API(method="post", action="", callbackMethod, Form=false, FormattedFormData= new FormData()){
    var xhr = new XMLHttpRequest();
    xhr.open(method.toUpperCase(), "/api"+action);
    
    // Set request headers and send form data
    if (Form){
        console.log("settings multipart");
        xhr.setRequestHeader('Content-Type', 'multipart/form-data');
        xhr.send(FormattedFormData);
    }else{
        xhr.send();        
    }


    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4 || xhr.code == 404){
            callbackMethod(xhr);
        }
    }
}

function SendFriendRequest(){
    var RecipientUsername = FriendSearchBar.value;
    var FormattedFormData = "RecipientUsername=" + RecipientUsername;

    console.log("Sending friend request to: " + RecipientUsername)
    API("post", "/FriendRequest", SendFriendRequestCB, true, FormattedFormData);
}

function SendFriendRequestCB(XHRrequest){
    var ResponseTextRaw = XHRrequest.responseText;
    var ResponseTextSerialized = JSON.parse(ResponseTextRaw);
    var Success = ResponseTextSerialized[0][1];

    FriendSearchBar.value = "";

    if (Success == "true"){
        alert("Friend request was a success!");
    }else{
        alert(ResponseTextSerialized[0][2])
    }
}

function FormatForm(formid){
    var FormattedData = new FormData();
    const Form = document.getElementById(formid);
    const FormChildren = Form.children;

    for (i = 0; i < FormChildren.length; i++){
        var SelectedChild = FormChildren[i];
        
        if(SelectedChild.nodeName == "INPUT"){
            FormattedData.append(SelectedChild.id, SelectedChild.value);
        }
    }

    return FormattedData;
} 

function LongPoll(){

}

function LongPollCB(XHRrequest){

    LongPoll();
}
function GetNav(){
    return document.getElementById("SideNav");
}

function ToggleNav(){
    var sidenav = GetNav();
    var sidenavWidth = sidenav.clientWidth;
    var sidenavMatrix = new WebKitCSSMatrix(window.getComputedStyle(sidenav).transform);

    switch (sidenavMatrix.m41){
        case 0:
            sidenav.style.transform = "translateX(" + -sidenavWidth + "px)";
            break;
        default:
            sidenav.style.transform = "translateX(0px)";
            break;
    }
}

function ToggleCategory(CallerDiv){
    var DivParent = document.getElementById(CallerDiv.id).parentElement;
    var DivChildren = DivParent.children;
    for(let i = 0; i < DivChildren.length; i++){
        var SelectedChild = DivChildren[i];

        if (SelectedChild.style.display == "none"){
            DisplayOption = "block"
        }else{
            DisplayOption = "none"
        }

        // Only execute for divs without the tag ID
        if (SelectedChild.id != CallerDiv.id){
            SelectedChild.style.display = DisplayOption;
        }
    }
}

function CloseNav(){
    var sidenav = GetNav();
    var sidenavWidth = sidenav.clientWidth;

    sidenav.style.transform = "translateX(" + -sidenavWidth + "px)";
}

function GetFriendsList(){
    API("post", "/get/friends-list", GetFriendsListCB);
    API("post", "/get/pending-friend-requests", GetPendingFriendRequestsCB);
}

function GetFriendsListCB(XHRrequest){
    const Friends = JSON.parse(XHRrequest.responseText);

    for (i = 0; i < Friends.length; i++){
        Username = Friends[i][0];
        SRC = Friends[i][1];      
        
        InsertItem("FriendsList", SRC, Username);
    }
}

function GetPendingFriendRequestsCB(XHRrequest){
    console.log(XHRrequest.responseText);
    ResponseTextSerialised = JSON.parse(XHRrequest.responseText);
    
    console.log(ResponseTextSerialised);
    for(i = 0; i < ResponseTextSerialised.length; i++){
        
    }
}

function InsertItem(parentid, imgsrc="", itemname=""){
    const ParentElement = document.getElementById(parentid);
    const NewDiv = document.createElement("div");
    const IMG = document.createElement("img");
    var UsernameElement = document.createElement("div");
    UsernameElement.style = "display:contents;";
    UsernameElement.innerHTML = itemname;

    IMG.src = imgsrc;
    IMG.alt = "Avatar";

    ParentElement.appendChild(NewDiv);
    
    NewDiv.addEventListener("click", function(Event){
        SelectItem(NewDiv);
    });

    NewDiv.appendChild(IMG);
    NewDiv.appendChild(UsernameElement);
    NewDiv.id = "Friend-" + Username;
    NewDiv.style = "width:100%; margin-top: 10%;display: none;";
}

function SelectItem(element){
    console.log("called by: "+element.id);
}
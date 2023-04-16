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

function CloseNav(){
    var sidenav = GetNav();
    var sidenavWidth = sidenav.clientWidth;

    sidenav.style.transform = "translateX(" + -sidenavWidth + "px)";
}




function SelectChat(element){
    console.log("called by: "+element.id);

}
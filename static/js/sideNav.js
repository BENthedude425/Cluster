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
    var VisibilityOption = "hidden";
    var DivParent = document.getElementById(CallerDiv.id).parentElement;
    var DivChildren = DivParent.children;
    for(let i = 0; i < DivChildren.length; i++){
        var SelectedChild = DivChildren[i];

        // Set the visibility option
        if(DivChildren[1].style.visibility == "hidden"){
            VisibilityOption = "visible";
        }

        // Only execute for divs without the tag ID
        if (SelectedChild.id != CallerDiv.id){
            SelectedChild.style.visibility = VisibilityOption;
        }
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
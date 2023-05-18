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

function SelectChat(element){
    console.log("called by: "+element.id);

}
//display modal on click

const modalWrapper = document.querySelector(".modals-wrapper");
if(modalWrapper){
    function displayModal(id) {
        console.log(id);
        const modal = document.getElementById(id);
        
        modalWrapper.style.display = "flex";
        modal.style.display = "flex";
        //close modal
        const close = document.getElementById("close-modal");
        close.addEventListener("click",() => {
            modalWrapper.style.display = "none";
            modal.style.display = "none";
        })
    }
}


//copy to clipboard
const copies = document.querySelectorAll(".copy");
copies.forEach(copy => {
    copy.addEventListener("click", () => {
        let elementToCopy = copy.previousElementSibling;
        elementToCopy.select();
        document.execCommand("copy");
    });
});

function toggleVisibility(id) {
    var x = document.getElementById(id);
    if (x.type === "password") {
      x.type = "text";
    } else {
      x.type = "password";
    }

  }

function generatePassword() {
    var passwordLength = 12;
    var charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]\:;?><,./-=";
    var password = "";
    for (var i = 0, n = charset.length; i < passwordLength; ++i) {
      password += charset.charAt(Math.floor(Math.random() * n));
    }
    document.getElementById("id_password").value = password;
  }

 
  function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
      .then(() => console.log('Copied to clipboard'))
      .catch((error) => console.error('Could not copy text: ', error));
  }
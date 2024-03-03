document.addEventListener("DOMContentLoaded", () => {
    const emailInput = document.getElementById("email");
    const emailForm = document.getElementById("emailForm");
    const submitBtn = document.getElementById("submitBtn");
    const validMsg = document.getElementById("valid");
    const invalidMsg = document.getElementById("invalid");

    submitBtn.addEventListener("click", () => {
        const email = emailInput.value;
        if (validateEmail(email)) {
            validMsg.innerText = "Email successfully set";
            invalidMsg.innerText = "";
            emailForm.submit();
        } else {
            invalidMsg.innerText = "Invalid email format";
            validMsg.innerText = "";
        }
    });

    function validateEmail(email) {     // Asked ChatGPT for this function in particular
        const re = /\S+@\S+\.\S+/;
        return re.test(email);
    }
});

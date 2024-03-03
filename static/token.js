function validateTokenFormat(token) {
    // Check if the token length is at least 19 characters
    if (token.length >= 19) {
        return true;
    } else {
        return false;
    }
}

// Function to handle form submission
function handleSubmit(event) {
    event.preventDefault(); // Prevent the form from submitting normally

    // Get the token input value
    var tokenInput = document.getElementById("token");
    var token = tokenInput.value.trim();

    // Validate the token format
    var isValidToken = validateTokenFormat(token);

    // Update the InvalidToken paragraph based on validation result
    var invalidTokenParagraph = document.getElementById("InvalidToken");
    if (isValidToken) {
        invalidTokenParagraph.textContent = ""; // Clear the error message
        // Submit the form (Asked ChatGPT for this line)
        event.target.submit();
    } else {
        invalidTokenParagraph.textContent = "Token must be at least 19 characters long."; // Display error message
    }
}

function startCooldown(button) {
    // Disable the button
    button.disabled = true;

    // Cooldown time in seconds
    var cooldown = 60;

    // Update the button text every second (Asked ChatGPT for this function)
    var countdown = setInterval(function() {
        button.textContent = `Wait ${cooldown} seconds`;
        cooldown--;

        // When the cooldown is over, enable the button and reset the text
        if (cooldown < 0) {
            clearInterval(countdown);
            button.textContent = 'Send Token';
            button.disabled = false;
        }
    }, 1000);

    // Submit the form
    button.closest('form').submit();
}


// Add event listener to the form for form submission
document.querySelector("form").addEventListener("submit", handleSubmit);

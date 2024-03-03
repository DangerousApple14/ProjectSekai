function timezoneSaved() {
    document.getElementById("valid").innerText = "Timezone saved!"
}

function displayUTCTime() {     // Asked ChatGPT how to create the datetime object
    var now = new Date();
    var utcTime = now.toUTCString();
    document.getElementById("utcTime").innerHTML = utcTime;
}

// Update the UTC time every second (asked ChatGPT how to update)
setInterval(displayUTCTime, 1000);

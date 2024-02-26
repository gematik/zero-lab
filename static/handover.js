
function connectListener(iss) {
    var schema
    if (window.location.protocol === "https:") {
        schema = "wss";
    } else {
        schema = "ws";
    }    
    issUrl = encodeURIComponent(iss);
    host = window.location.host;
    var ws = new WebSocket(`${schema}://${host}/reg/auth/gematik-fed/handover-listener?iss=${issUrl}`);
    var interval = null;
    // receive messages
    ws.onmessage = function (event) {
        const message = JSON.parse(event.data);
        console.log(message);
        if (message['type'] == 'HandoverAuth') {
            showHandoverCode(message['payload']['auth_url']);
            interval = showCountdown(600)
        } else if (message['type'] == 'HandoverToken') {
            clearInterval(interval);
            showToken(message['payload']);
        } else if (message['type'] == 'HandoverError') {
            clearInterval(interval);
            alert(message['payload']['error'])
        }
    }
}

function showCountdown(countdownSeconds) {
    const elem = document.getElementById('countdown');

    function secondsToString(seconds) {
        var minute = Math.floor(seconds / 60);
        var second = seconds - minute * 60;
        // padding
        if (minute < 10) {
            minute = '0' + minute;
        } 
        if (second < 10) {
            second = '0' + second;
        }    
        return minute + ':' + second;
    }

    elem.innerHTML = secondsToString(countdownSeconds);

    var interval = setInterval(function() {
        if (countdownSeconds <= 0) {
            clearInterval(interval);
            // refresh page
            location.reload();
            return;
        }
        countdownSeconds--;
        elem.innerHTML = secondsToString(countdownSeconds);
    }
    , 1000);

    return interval;
}


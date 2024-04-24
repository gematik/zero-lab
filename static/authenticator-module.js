export async function startDecoupledAuth(authURL) {
    var url = new URL('/web/login/poll', window.location.href).href;

    window.open(authURL, '_self');

    // start polling
    var interval = setInterval(async function() {
        var pollResponse = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
            })
        }).then(async response => { 
            if (response.status != 200 && response.status != 202) {
                clearInterval(interval);
                const body = await response.json();
                // redirect to error page with error and error description, url escaped
                window.location.href = '/web/error?error=server_error&error_description='+encodeURIComponent(body['error_description']);
                return;
            }
            return response.json()
        } )
        .catch(error => { 
            console.log(error);
            return;
        });
        if (pollResponse == null || pollResponse['error'] != null) {
            return;
        }
        console.log(pollResponse);
        clearInterval(interval);
        window.location.href = '/web/protected/userinfo';
    }, 2000);
}


export async function startDecoupledAuth(iss) {
    var url = new URL('/web/auth-decoupled', window.location.href).href;

    var grantResponse = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            'grant_type': 'urn:telematik:params:grant-type:decoupled',
            'op_issuer': iss,
        })
    }).then(response => response.json())
    .catch(error => alert(error));

    if (grantResponse == undefined) {
        window.location.href = '/web/error?error=server_error';
        return;
    }

    if (grantResponse['error'] != undefined) {
        // redirect to error page with error and error description, url escaped
        window.location.href = '/web/error?error=' + encodeURIComponent(grantResponse['error']) + '&error_description=' + encodeURIComponent(grantResponse['error_description']);
        return;
    }

    window.open(grantResponse['redirect_uri'], '_self');

    // start polling
    var interval = setInterval(async function() {
        var tokenResponse = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                'auth_req_id': grantResponse['auth_req_id']
            })
        }).then(response => response.json())
        .catch(error => { 
            console.log(error);
            // redirect to error page with error and error description, url escaped
            window.location.href = '/web/error?error=server_error&error_description='+encodeURIComponent(error);
            clearInterval(interval);
            return;
        });
        if (tokenResponse == undefined) {
            return;
        }
        if (tokenResponse['error'] == 'authorization_pending') {
            return;
        }
        console.log(tokenResponse);
        clearInterval(interval);
        // redirect to success page with token, url escaped
        window.location.href = '/web/userinfo';
    }, grantResponse['interval'] * 1000);
}


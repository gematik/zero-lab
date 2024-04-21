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
        alert('Error during auth')
        return;
    }

    if (grantResponse['error'] != undefined) {
        alert(grantResponse['error']);
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
            alert(error)
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
    }, grantResponse['interval'] * 1000);
}


import DPoP, { generateKeyPair } from  "/static/libs/dpop.js";

var clientId = 'gematik-fed-auth-client-TODO';
var dpopKeypair = null;

export async function generateJOSEIdentity() {
    dpopKeypair = await generateKeyPair("ES256");
}

export function createDPoP(htu, htm, nonce, accessToken, additional) {
    return DPoP(dpopKeypair, htu, htm, nonce, accessToken, additional);
}

export async function startDeviceCodeFlow(iss) {
    var url = new URL('/reg/auth/gematik-fed/device/code', window.location.href).href;
    var dpop = await createDPoP(url, 'POST', undefined, undefined, undefined)

    var deviceResponse = await fetch(url, {
        method: 'POST',
        headers: {
            'DPoP': dpop,
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            'iss': iss,
            'client_id': clientId,
        })
    }).then(response => response.json())
    .catch(error => alert(error));
    if (deviceResponse == undefined) {
        alert('Error during device code flow')
        return;
    }
    showHandoverCode(deviceResponse['verification_uri_complete']);
    // start polling
    var interval = setInterval(async function() {
        var url = new URL('/reg/auth/gematik-fed/device/token', window.location.href).href;
        var dpop = await createDPoP(url, 'POST', undefined, undefined, undefined)
        var tokenResponse = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'DPoP': dpop
            },
            body: new URLSearchParams({
                'iss': iss,
                'client_id': clientId,
                'device_code': deviceResponse['device_code']
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
        showToken(tokenResponse);
    }, deviceResponse['interval'] * 1000);
}

export function showIdentityProviders() {
    fetch('/reg/auth/gematik-fed/identity-providers')
        .then(response => response.json())
        .then(data => {
            const listElem = document.getElementById('identity-providers-list');
            listElem.innerHTML = '';
            const idpList = data;
            idpList.forEach(idp => {
                const idpElem = document.createElement('div');
                idpElem.classList.add('idp');
                var logoStyle = '';
                if (idp.logo_uri == "") {
                    idp.logo_uri = '/static/images/healthid_logo.png';
                    logoStyle = 'border-radius: 15%;';
                }
                idpElem.innerHTML = `
                    <img src="${idp.logo_uri}" alt="${idp.title}" style="${logoStyle}" />
                    <label>${idp.title}</label>
                    <i class="chevron fas fa-chevron-right"></i>
                `;
                idpElem.addEventListener('click', () => {
                    selectIdentityProvider(idp.iss);
                });
                listElem.appendChild(idpElem);
            });
        }
    );
}

export function selectIdentityProvider(iss) {
    document.getElementById('identity-providers').style.display = 'none';
    const elem = document.getElementById('handover-code')
    elem.style.display = 'block';
    elem.getElementsByClassName('fa-spinner')[0].style.display = 'inline-block';
    startDeviceCodeFlow(iss);
    //connectListener(iss);
}

function showHandoverCode(link) {
    const linkElem = document.getElementById("handover-auth-link");
    linkElem.innerHTML = `<a href=${link}>Authenticate without handover</a>`
    const elem = document.getElementById('handover-code-wrapper');
    elem.getElementsByClassName('fa-spinner')[0].style.display = 'none';

    qrCode.append(document.getElementById('handover-code-wrapper'));
}

function showToken(response) {
    document.getElementById('handover-code').style.display = 'none';
    const elem = document.getElementById('handover-token');
    elem.style.display = 'block';
    const token = response['tmp_id_token'];
    // split token into 3 parts
    const tokenParts = token.split('.');
    // decode header and claims
    const header = JSON.parse(atob(tokenParts[0]));
    const claims = JSON.parse(atob(tokenParts[1]));
    // pretty header and claims
    const headerPretty = JSON.stringify(header, null, 2);
    const claimsPretty = JSON.stringify(claims, null, 2);

    elem.getElementsByClassName('id-token')[0].innerHTML = token;
    elem.getElementsByClassName('id-token-header')[0].innerHTML = headerPretty;
    elem.getElementsByClassName('id-token-claims')[0].innerHTML = claimsPretty;
    elem.getElementsByClassName('user-agent')[0].innerHTML = navigator.userAgent;
}

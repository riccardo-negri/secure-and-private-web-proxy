var result = document.getElementById('result');
var mrSigner = document.getElementById('mr-signer');
var mrEnclave = document.getElementById('mr-enclave');
var iasReport = document.getElementById('ias-report');
var fullCert = document.getElementById('full-cert');

function request(resource, key) {
    const request = browser.runtime.sendMessage({
        type: 'ra-tls-request',
        resource: resource,
        key: key
    });
    return request;
}

function updatePopup(tabInfo) {
    mrSigner.innerText = 'Loading...';
    mrEnclave.innerText = 'Loading...';

    request('mr-signer', tabInfo.id)
        .then(response => {
            if (response.get("verified")) {
                result.innerText = 'Enclave attestation and signature verified';
                result.style.color = '#00FF00';

                mrSigner.innerText = response.get("mrSigner");
                mrEnclave.innerText = response.get("mrEnclave");
                iasReport.innerText = response.get("iasReport");
                fullCert.innerText = response.get("fullCert");
            }
            else {
                result.innerText = 'Could not verify successfully attestation and signature';
                result.style.color = '#FF0000';

                // hide the mr-signer and mr-enclave
                mrSigner.parentNode.innerText = '';
                mrEnclave.parentNode.innerText = '';
                iasReport.parentNode.innerText = '';
                fullCert.parentNode.innerText = '';
            }
            
        }).catch(error => console.error(error));   
}

browser.tabs.query({active: true, windowId: browser.windows.WINDOW_ID_CURRENT})
  .then(tabs => browser.tabs.get(tabs[0].id))
  .then(tab => {
    updatePopup(tab);
  });

function copy(id) {
    let copyText = document.querySelector(id);
    console.log(copyText.innerHTML);
    navigator.clipboard.writeText(copyText.innerHTML);
}

document.querySelector("#mr-enclave-button").addEventListener("click", function() {
    copy("#mr-enclave");
});

document.querySelector("#mr-signer-button").addEventListener("click", function() {
    copy("#mr-signer");
});

document.querySelector("#ias-report-button").addEventListener("click", function() {
    copy("#ias-report");
});

document.querySelector("#full-cert-button").addEventListener("click", function() {
    copy("#full-cert");
});
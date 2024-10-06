const https = require('https');
const fs = require('fs');
const { Certificate } = require('@fidm/x509');
const { pki, md, util } = require('node-forge');
const { Buffer } = require('buffer');
const { assert } = require('console');
const crypto = require('crypto');

tabsPopupInfo = new Map();

async function fetchPemFile(filePath) {
    const response = await fetch(filePath);
    const pemText = await response.text();
    return pemText;
}

function derToPem(der) {
    const b64 = Buffer.from(der).toString('base64');
    const pem = b64.match(/.{1,64}/g).join('\n');
    return pem;
}

function parseBinaryData(buffer, offset, length) {
    return buffer.slice(offset, offset + length);
}


async function updateIcon(tabId) {
    console.log('Updating icon');
    if (tabsPopupInfo.get(tabId) != undefined && tabsPopupInfo.get(tabId).get('verified') != undefined && tabsPopupInfo.get(tabId).get('verified')) {
        console.log('Setting icon to verified');
        browser.pageAction.setIcon({
            tabId: tabId, path: "icons/verified.png"
        });
    } 
    else {
        console.log('Setting icon to unverified');
        browser.pageAction.setIcon({
            tabId: tabId, path: "icons/unverified.png"
        });
    } 
}

async function getCertificateInfo(details) {
    const tabId = details.tabId;
    if (!tabsPopupInfo.has(tabId)) {
        tabsPopupInfo.set(tabId, new Map());
        tabsPopupInfo.get(tabId).set('verified', false);
    }
    const tabInfoMap = tabsPopupInfo.get(tabId);
    try {
        const securityInfo = await browser.webRequest.getSecurityInfo(
            details.requestId,
            {   
                certificateChain: false,
                rawDER: true
            });
        console.log(securityInfo);

        if (securityInfo.state !== 'secure') {
            console.error("The connection is not secure.");
            throw new Error("The connection is not secure.");
        }

        // fetch the root CA public key PEM file
        const rootCertPEM = await fetchPemFile('./Intel_SGX_Attestation_RootCA.pem');
        const rootCert = pki.certificateFromPem(rootCertPEM);
        console.log("Root CA public key PEM file: \n", rootCertPEM);

        // get the certificate to verify
        const certDer = securityInfo.certificates[0].rawDER;
        console.log("Cert to verify: \n", certDer);

        // convert DER to PEM
        certPEM = "-----BEGIN CERTIFICATE-----\n" + derToPem(certDer) + "\n-----END CERTIFICATE-----";
        console.log("Cert PEM to verify: \n", certPEM);

        // extensions structure
        //
        // 1.2.840.113741.1337.2
        // contains the attestation report returned by IAS (Intel Attestation Service)
        // within it the field isvEnclaveQuoteBody contains the actual quote sent by the enclave to IAS
        // 
        // The structure of the quote is as follows:
        // typedef struct _quote_t
        // {
        //     uint16_t            version;        /* 0   */
        //     uint16_t            sign_type;      /* 2   */
        //     sgx_epid_group_id_t epid_group_id;  /* 4   */
        //     sgx_isv_svn_t       qe_svn;         /* 8   */
        //     sgx_isv_svn_t       pce_svn;        /* 10  */
        //     uint32_t            xeid;           /* 12  */
        //     sgx_basename_t      basename;       /* 16  */
        //     sgx_report_body_t   report_body;    /* 48  */
        //     uint32_t            signature_len;  /* 432 */
        //     uint8_t             signature[];    /* 436 */
        // } sgx_quote_t;
        //
        // Inside the sgx_report_body_t structure, the field report_data contains the actual report data
        // The report data is a structure of type sgx_report_data_t
        // typedef struct _report_body_t
        // {
        //     sgx_cpu_svn_t           cpu_svn;        /* (  0) Security Version of the CPU */
        //     sgx_misc_select_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
        //     uint8_t                 reserved1[12];  /* ( 20) */
        //     sgx_isvext_prod_id_t    isv_ext_prod_id;/* ( 32) ISV assigned Extended Product ID */
        //     sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
        //     sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
        //     uint8_t                 reserved2[32];  /* ( 96) */
        //     sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
        //     uint8_t                 reserved3[32];  /* (160) */
        //     sgx_config_id_t         config_id;      /* (192) CONFIGID */
        //     sgx_prod_id_t           isv_prod_id;    /* (256) Product ID of the Enclave */
        //     sgx_isv_svn_t           isv_svn;        /* (258) Security Version of the Enclave */
        //     sgx_config_svn_t        config_svn;     /* (260) CONFIGSVN */
        //     uint8_t                 reserved4[42];  /* (262) */
        //     sgx_isvfamily_id_t      isv_family_id;  /* (304) ISV assigned Family ID */
        //     sgx_report_data_t       report_data;    /* (320) Data provided by the user */
        // } sgx_report_body_t;
        //
        // The report_data field contains the SHA256 of the public key of the enclave
        // 
        // 1.2.840.113741.1337.3
        // contains the IAS root CA
        // should be exactly what I have in the root CA PEM file
        //
        // 1.2.840.113741.1337.4
        // contains a certificate for the IAS report signing key
        //
        // 1.2.840.113741.1337.5
        // contains the IAS report signature

        // steps to perform to verify the whole chain of trust
        // 1. verify the certificate with the IAS report signing key (1.2.840.113741.1337.4)
        // 2. verify the report with the report signature and public key from above cert (1.2.840.113741.1337.5)
        // 3. extract the enclave public key from the report data and compare it with the public key used for the whole certificate (1.2.840.113741.1337.2)
        // 4. extract the enclave identity and compare it with what is expected

        // extract and print extensions
        const cert = Certificate.fromPEM(Buffer.from(certPEM));
        console.log("Certificate extensions: ");
        cert.extensions.forEach(extension => {
            console.log(extension);

            // print body of the extension decoded
            const decoded = extension.value.toString('utf8');
            console.log(decoded);
        });

        // 1. verify the certificate with the IAS report signing key (1.2.840.113741.1337.4)
        const iasReportSigningKeyCertPEM = cert.getExtension('1.2.840.113741.1337.4').value;
        const iasReportSigningKeyCert = pki.certificateFromPem(iasReportSigningKeyCertPEM);
        verified = rootCert.verify(iasReportSigningKeyCert);
        console.log('Certificate verification result for IAS report signing key:', verified);
        assert(verified, 'IAS report signing key verification failed');

        // 2. verify the report with the report signature and public key from above cert 
        const iasReportSignatureBase64 = cert.getExtension('1.2.840.113741.1337.5').value.toString('utf8');
        const iasReportSignature = Buffer.from(iasReportSignatureBase64, 'base64');
        
        const publicKey = iasReportSigningKeyCert.publicKey;

        const iasReport = cert.getExtension('1.2.840.113741.1337.2').value.toString('utf8');
        const tmpMd = md.sha256.create();
        tmpMd.update(iasReport, 'utf8');

        verified = publicKey.verify(tmpMd.digest().bytes(), iasReportSignature);
        console.log('Signature verification result:', verified);
        assert(verified, 'Signature verification failed');

        // 3. extract the enclave public key from the report data and compare it with the public key used for the whole certificate
        const iasReportObj = JSON.parse(iasReport);
        const isvEnclaveQuoteBody = iasReportObj.isvEnclaveQuoteBody;
        console.log('isvEnclaveQuoteBody:', isvEnclaveQuoteBody);

        // extract the quote data
        quoteData = Buffer.from(isvEnclaveQuoteBody, 'base64');
        console.log('Quote data:', quoteData);

        // report body starts at offset 48
        // report data starts at offset 320 relative to the start of the report body
        // report data has a length of 32 bytes (sha256 digest)
        const reportData = parseBinaryData(quoteData, 48 + 320, 32);
        const digestFromReport = reportData.toString('hex');
        console.log('Report data (SHA256 digest of public key):', digestFromReport);

        // get public key used in the certificate
        // by looking into ra-tls code, the length should be 398 bytes 
        const publicKeyCert = cert.publicKey;
        console.log('Public key in the certificate:', publicKeyCert);
        var publicKeyRaw = publicKeyCert.keyRaw;
        console.log('Public key in the certificate:', publicKeyRaw);

        // get the digest of the pubkey in the certificate
        const hash = crypto.createHash('sha256');
        hash.update(publicKeyRaw);
        const digest = hash.digest('hex');
        console.log('SHA-256 Digest:', digest);

        // compare the two digests
        assert(digest === digestFromReport, 'Public key mismatch');
        console.log('Public key matches!');

        // 4. extract the enclave identity 
        // need to parse the info from quoteData
        // mr_enclave is at offset 48 + 64
        // mr_enclave has a length of 32 bytes
        const mrEnclave = parseBinaryData(quoteData, 48 + 64, 32);
        console.log('mr_enclave:', mrEnclave.toString('hex'));

        // mr_signer is at offset 48 + 128
        // mr_signer has a length of 32 bytes
        const mrSigner = parseBinaryData(quoteData, 48 + 128, 32);
        console.log('mr_signer:', mrSigner.toString('hex'));

        // set info into the map
        tabInfoMap.set('verified', true);
        tabInfoMap.set('mrSigner', mrSigner.toString('hex'));
        tabInfoMap.set('mrEnclave', mrEnclave.toString('hex'));
        tabInfoMap.set('iasReport', iasReport);
        tabInfoMap.set('fullCert', certPEM.replace(/\n/g, ''));
    } catch (error) {
        console.error(error);
    }
    await updateIcon(tabId);
}

function handleMessage(request, sender, sendResponse) {
    var res = tabsPopupInfo.get(request.key);
    console.log('Sending response:', res);
    sendResponse(tabsPopupInfo.get(request.key));
}

browser.webRequest.onHeadersReceived.addListener(getCertificateInfo,
    {urls: ["https://*/*"]}, ["blocking", "responseHeaders"]
);

browser.runtime.onMessage.addListener(handleMessage);

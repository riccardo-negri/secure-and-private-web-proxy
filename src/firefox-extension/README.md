# Firefox Extension to Verify Remote Attestation Certificates
[Browserify](https://browserify.org/) is used to bundle the JavaScript code for the extension. The extension is developed using the [web-ext](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Getting_started_with_web-ext) tool provided by Mozilla.

## Development
Generate the code with `browserify ra-tls-checker-pre-browserify.js -o ra-tls-checker.js`.

Run the command `web-ext run` in the `src/firefox-extension` directory to start the development server. This will open a new Firefox window with the extension installed. Any changes you make to the extension will be automatically reloaded in the browser.

To see the console output of the extension, in the browser that just opened, navigate to `about:debugging`, click on `This Firefox` and click on the `Inspect` button next to the extension.
This will open a new window with the developer tools for the extension including the console tab.

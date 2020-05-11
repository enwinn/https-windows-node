/*
 * 
 * How to use self-signed certificates on Windows 10 v1809 with NodeJS
 * using the built-in SChannel Provider mechanisms in lieu of installing and using openssl
 * 
 * Author: Eric N. Winn
 * 
 * Testing using a PowerShell generated self-signed certificate generated on Windows 10
 * ref: https://www.petri.com/create-self-signed-certificate-using-powershell 
 * ref: https://stackoverflow.com/a/50762069 
 * ref: https://stackoverflow.com/a/23125101 
 * ref: hosts file contains: 127.0.0.1  frodo.local  frodo  # Dummy site for node.js https testing. See https://stackoverflow.com/a/50762069
 * ref: Run these after the hosts file update:
 *      ipconfig /flushdns
 *      nbtstat -R
 *      ping frodo.local
 * ref: $cert = New-SelfSignedCertificate -CertStoreLocation "cert:\LocalMachine\My" -DnsName "frodo.local" -FriendlyName "frodo"
 * ref: $pwd = ConvertTo-SecureString -String ‘Sauron is a bully!’ -Force -AsPlainText
 * ref: $path = 'cert:\LocalMachine\My\' + $cert.thumbprint 
 * ref: Export-PfxCertificate -cert $path -FilePath C:\sourcecode\nodeJS\https-windows-2\pki\frodo.local.pfx -Password $pwd
 * 
 * For Microsoft Internet Explore, Edge Classic, and Firefox (configured to use local certificate store trusts)
 * 
 *   You need to copy or import frodo.acus.dev into the Local Computer's Trusted Root Certificate Authorities certificate store
 * 
 *   Import-PfxCertificate -FilePath C:\sourcecode\nodeJS\https-windows-2\pki\frodo.local.pfx Cert:\LocalMachine\Root -Password $pwd
 * 
 * For Microsoft Edge Chromium and Google Chrome
 * 
 *   You need to import frodo.acus.dev into the Current User's Personal Certificate Store 
 * 
 *   Import-PfxCertificate -FilePath C:\sourcecode\nodeJS\https-windows-2\pki\frodo.local.pfx Cert:\CurrentUser\My -Password $pwd
 */

// Dependencies
const http = require('http');
const https = require('https');
const { URL, URLSearchParams } = require('url');
const StringDecoder = require('string_decoder').StringDecoder;
const config = require('./config');
const fs = require('fs');

// Instantiating the HTTP server
const httpServer = http.createServer( (req,res) => {
  unifiedServer(req,res);
});

// Start the HTTP server and listen on the configuration mode port
httpServer.listen(config.httpPort, () => {
  console.log(`The HTTP server is listening on port ${config.httpPort} in ${config.envName} mode`);
});

// Set the HTTPS config options
const httpsServerOptions= {
  pfx: fs.readFileSync('./pki/frodo.local.pfx'),
  passphrase: 'Sauron is a bully!'
}

// Instantiate the HTTPS server
const httpsServer = https.createServer( httpsServerOptions, (req,res) => {
  unifiedServer(req,res);
});

// Start the HTTPS server and listen on the configuration mode port
httpsServer.listen(config.httpsPort, () => {
  console.log(`The HTTPS server is listening on port ${config.httpsPort} in ${config.envName} mode`);
});

// Unified http and https functionality
const unifiedServer = (req,res) => {

  // Check for authorization header content
  function buildUri() {
    if (req.headers && req.headers.authorization) {
      const header=req.headers.authorization;
      const token=header.split(/\s+/).pop()||'';
      const auth = new Buffer.from(token, 'base64').toString();
      const parts=auth.split(/:/);
      const username=parts[0];
      const password=parts[1];
      console.log(`Auth info:
        username: ${username}
        password: ${password}`);
        return  `http://${username}:${password}@${req.headers.host}${req.url}`;
    }
    else {
      return `http://${req.headers.host}${req.url}`;
    }
  }

  // Get the URL and parse it
  const baseURL = buildUri();
  const parsedURL = new URL(req.url, baseURL);

  // Get the path from the URL
  const path = parsedURL.pathname;
  const trimmedPath = path.replace(/^\/+|\/+$/g,'');

  // Get the query string using URLSearchParams
  const searchParams = new URLSearchParams(parsedURL.searchParams);

  // Get the HTTP Method
  const method = req.method.toUpperCase();

  // Get the headers as an object
  const headers = req.headers;

  // Get the payload, if any
  const decoder = new StringDecoder('utf-8');
  let buffer = '';
  req.on('data', (data) => {
    buffer += decoder.write(data);
  });
  req.on('end', () => {
    buffer += decoder.end();

    // Choose the handler this request should go to.
    // If one is not found, use the notFound handler
    const chosenHandler = typeof(router[trimmedPath]) != 'undefined' ? router[trimmedPath] : handlers.notFount;

    // Construct the data object to send to the handler
    const data = {
      'trimmedPath' : trimmedPath,
      'searchParams' : searchParams,
      'method' : method,
      'headers' : headers,
      'payload' : buffer
    };

    // Route the request to the handler specified in the router
    chosenHandler(data, (statusCode, payload) => {
      // Use the status code called back by the handler, or default to 200
      statusCode = typeof(statusCode) == 'number' ? statusCode : 200;

      // Use the payload called back by the handler, or default to an empty object
      payload = typeof(payload) == 'object' ? payload : {};

      // Convert the payload to a string
      const payloadString = JSON.stringify(payload);

      // Return the response
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'X-Frame-Options');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Content-Security-Policy', "default-src 'self'");
      res.writeHead(statusCode);
      res.end(payloadString);

      // Populate the console content
      const parsedResponse = (`Hello, here are your request details:

      parsedURL.hash.........: ${parsedURL.hash}
      parsedURL.host.........: ${parsedURL.host}
      parsedURL.hostname.....: ${parsedURL.hostname}
      parsedURL.href.........: ${parsedURL.href}
      parsedURL.origin.......: ${parsedURL.origin}
      parsedURL.password.....: ${parsedURL.password}
      parsedURL.pathname.....: ${parsedURL.pathname}
      parsedURL.port.........: ${parsedURL.port}
      parsedURL.protocol.....: ${parsedURL.protocol}
      parsedURL.search.......: ${parsedURL.search}
      parsedURL.searchParams.: ${parsedURL.searchParams}
      parsedURL.username.....: ${parsedURL.username}
      parsedURL.toString()...: ${parsedURL.toString()}

      path...................: ${path}
      trimmedPath............: ${trimmedPath}
      method.................: ${method}
      searchParams...........: ${searchParams.toString()}
      headers................: \n${JSON.stringify(headers,null, 2)}
      payload................: ${buffer}\n`);

      // Log the request details
      console.log(parsedResponse+'\n');
      console.log('Returning this response: ', statusCode, payloadString);

    });
  });
};

// Define the handlers
const handlers = {};

// Ping handler
handlers.ping = (data, callback) => {
  // Don't care about a payload, just respond with OK
  callback(200);
};

// Not found handler
handlers.notFount = (data, callback) => {
  callback(404);
};

// Define a request router
const router = {
  'ping' : handlers.ping
};

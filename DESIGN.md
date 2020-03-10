# TLSential Design Doc

## Diagram

+--------------------+
| Web                |
+--------------------+
   |^    ^         ^
   ||    |         |
   ||    |         |
(-------------------)
( Firewall          )
(-------------------)
   ||    |         |
   ||    |         |
   v|    |         |
  +--+ +--+ +--+   |
  |WS| |WS| |WS|   |
  +--+ +--+ +--+   |
   ||   ||   ||    |
+--------------------+
| TLSential          |
+--------------------+

WS = Web Server


## Introduction

TLSential is a webservice designed to be hosted within a firewalled network.
This app should not be publicly accessible but must be able to reach out to
public ACME servers. Any webservers wishing to get TLS certificates must be able
to reach out to TLSential.

## Usage

### Creating a New Certificate

Using the TLSential web UI (TODO: add API?), create a new certificate by,
1. Adding a list of all domains (including specific subdomains)
Ex. [www.example.com, example.com]

2. Click "Generate"

This will begin the process of reaching out via ACME to get the challenge token,
then creating the necessary DNS entry via API token, then retrieving the TLS
cert via ACME.

All of the ACME process is done using the LEGO library.

The certificate will now either be ready for download (via API or web UI), or
there will be an error message displayed.

### Deploying the Certificate

Once a new certificate has been configured, a cryptographically secure secret
token will be generated and associated with this certificate. Downloading the
certificate can be done via API call by providing the secret token.

This allows access to ONLY this certificate.

Convenience scripts will be provided to allow for the retrieval and deployment
of specific certificates on clients.

Ie. 
    wget "https://tlsential/script/{script-id}?token={cert-token}" -O deploy.sh && sudo bash deploy.sh {cert-token}

deploy.sh will be a script that, when called, will reach out to download the
appropriate certificate, move it to a preconfigured spot (ie.
/etc/nginx/pki/privkey.pem)
and then set up both a cron job for renewal, and also restart nginx.

Other convenience scripts can be created or edited for M$ or other flavors of
linux or webserver.

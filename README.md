# TLS Scanner
Scan an HTTP endpoint to output the HTTP
responses from common paths and find unauthenticated emthods.

## Usage
This script is not intended for malicious use and should only be
used to scan host names and endpoints that you have permission
to scan.

The authors of this script are not responsible for its usage.

For usage see: tls_scanner.py -h

### HTTPS Scanning
By default ports 443 and 8443 will attempt an HTTPS connection with various
TLS versions. The default TLS version is 1.2 but you can use --tls_ver 1.3
to make connections with TLS 1.3 (for example) and fetch content and
the certificate.

Using debug mode will display HTTP header values, but only for the
selected TLS version (defaulting to 1.2) so the output is not excessive.

### HTTPS Certificates
Any HTTPS connection attempt will attempt to fetch a certificate as well. A
certificate that is expired will be shown in the output by default. Enabling
debug mode will display the certificate expiry in UTC.

## Modifications
Like most python development, it's recommended to use a virtual env.

1. Clone the repo
2. python3 -m venv env
3. source env/bin/activate
4. pip install -r requirements.txt


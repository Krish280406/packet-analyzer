# Notes

## How a flow gets classified
- Port 443: read SNI from TLS ClientHello, then map the name to an app
- Port 80: read the Host header from the HTTP request
- Port 53: read the domain from the DNS query
- Once a flow is classified, later packets reuse the result

## Things to fix later
- HTTP flows are labelled HTTPS
- DNS lookups are not classified by domain
- Server replies are a separate flow and stay Unknown

# CertLab — آزمایشگاه گواهی SSL و CSR

A privacy-first, open-source certificate inspection app by Mehrdad32. Styled like TarikhDaar.

**Website:** https://certlab.mehrdad32.ir/

## Features
- Inspect X.509 certificates (PEM / CRT / CER / DER) and PKCS#10 CSRs (PEM / CSR / DER).
- Parse multiple certificates in a PEM bundle.
- Show subject, issuer, serial, validity, SAN, algorithms, extensions and SHA-256 fingerprint.
- Verify CSR signatures with WebCrypto where supported.
- Inspect entirely in the browser without uploading files, contacting APIs or loading remote fonts.
- Copy summaries and download JSON reports.

## Scope & safety
- This tool does NOT validate the browser/OS trust store, certificate chains, hostname matching, or revocation (OCSP/CRL).
- Date validity does NOT mean a certificate is trusted.
- Private keys and PKCS#12 archives are deliberately not supported.
- A static browser app cannot directly retrieve a remote server's TLS handshake certificate.

## Development
Requires Node.js 22 or newer.
Commands: npm install; npm test; npm run build; npm run dev.

## Cloudflare Pages
Repository: Mehrdad32/CertLab
Production branch: main
Root directory: repository root (leave unset)
Framework: React (Vite)
Build command: npm run build
Output directory: dist
Node: 22.23.4 (NODE_VERSION variable if necessary)
Domain: certlab.mehrdad32.ir

License: MIT (see LICENSE).

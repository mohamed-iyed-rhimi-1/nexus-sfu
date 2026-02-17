# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

**Do not open a public issue.**

Email the maintainers directly with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

Security-relevant areas of Nexus SFU include:
- SRTP/DTLS encryption and key handling
- ICE credential validation
- JWT authentication in the REST API
- QUIC TLS configuration
- Input validation on all network-facing parsers (RTP, RTCP, STUN, SDP)

# Security Policy

## Reporting a Vulnerability

To report a security vulnerability, please email security@fang.security or open a confidential issue on GitHub.

Do not disclose security vulnerabilities publicly until they have been addressed by the maintainers.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Security Measures

- All communications use TLS 1.3
- Passwords are hashed with bcrypt
- API keys are generated using cryptographic random generators
- Database files are stored with restricted permissions (0600)
- Session tokens are securely generated and stored
- Regular security audits are performed on dependencies

## Disclosure Timeline

We aim to respond to vulnerability reports within 48 hours and release patches within 14 days of confirmation.

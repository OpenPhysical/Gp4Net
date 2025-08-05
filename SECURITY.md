# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Gp4Net, please report it responsibly:

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email security reports to: [security@mistial.dev](mailto:security@mistial.dev)
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested fix (if known)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Regular Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical issues within 30 days

### Security Measures

Gp4Net implements several security measures:

- **Functional Programming**: Eliminates null reference exceptions and many runtime errors
- **Input Validation**: All external data is validated using Result<T> patterns
- **Cryptographic Security**: Uses BouncyCastle for all cryptographic operations
- **No Secrets in Code**: All test data uses well-known test vectors
- **Immutable Data**: All data structures are immutable to prevent tampering

### Vulnerability Disclosure

Once a security vulnerability is fixed:

1. We will publish a security advisory on GitHub
2. Release notes will include security fix information
3. CVE numbers will be assigned for significant vulnerabilities
4. Credit will be given to security researchers (with permission)

### Security Best Practices for Users

When using Gp4Net:

- Always validate smart card responses
- Use secure key storage for production keys
- Implement proper access controls
- Keep the library updated to the latest version
- Follow GP specification security guidelines
- Use secure channels (SCP02/SCP03) for sensitive operations

### Scope

This security policy covers:

- The Gp4Net library code
- Command-line tool security
- Cryptographic implementations
- Input validation and error handling

This policy does not cover:

- Third-party dependencies (report to respective maintainers)
- Hardware-specific smart card vulnerabilities
- User application security (beyond library usage)

### Contact

For security-related questions or concerns:
- Email: [security@mistial.dev](mailto:security@mistial.dev)
- GPG Key: Available upon request

Thank you for helping keep Gp4Net secure!
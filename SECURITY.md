# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within BYMA TOOLS, please send an email to the maintainers. All security vulnerabilities will be promptly addressed.

**Please do NOT report security vulnerabilities through public GitHub issues.**

## Security Guidelines

### For Users

1. **Authorization**: Only use this tool on systems you own or have explicit written permission to test.

2. **Legal Compliance**: Ensure compliance with all applicable local, state, national, and international laws.

3. **Responsible Disclosure**: Report any discovered vulnerabilities to the system owner before public disclosure.

4. **Data Protection**: Handle any discovered data (passwords, tokens, etc.) responsibly and securely.

5. **Documentation**: Keep records of all authorized testing activities.

### For Developers

1. **Code Review**: All code changes must be reviewed before merging.

2. **Dependency Updates**: Regularly update dependencies to patch security issues.

3. **Input Validation**: Always validate and sanitize user inputs.

4. **Secure Defaults**: Use secure default configurations.

5. **No Hardcoded Secrets**: Never commit API keys, passwords, or other secrets.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Features

- All scans are logged for audit purposes
- Rate limiting to prevent abuse
- Input validation on all parameters
- No credentials stored in plaintext
- Secure database connections

## Best Practices

```bash
# Run with minimal permissions
python main.py recon subdomain example.com

# Avoid aggressive scans without authorization
# Use stealth mode for authorized testing only
python main.py stealth --scan target
```

## Contact

For security concerns, contact: [GitHub Issues](https://github.com/AbymanyuNWR/BYMA-TOOLS-CYBER/issues)

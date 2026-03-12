# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in DataVault, please **DO NOT** open a public GitHub issue.

Instead, please report it responsibly by emailing:

**📧 abuse@osintintelligence.xyz**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

We take security seriously and will respond to all vulnerability reports promptly.

---

## Security Best Practices for Users

### API Keys & Configuration

- Never commit `.env` files with API keys
- Use environment variables for sensitive credentials
- Keep `.env` out of version control (it's in `.gitignore`)
- Rotate API keys regularly

### Data Handling

- This tool collects data from multiple sources
- Ensure you have authorization before scanning targets
- Review exported data before sharing
- Be aware of rate limits on free APIs

### Network Security

- All API calls use HTTPS
- Never use unencrypted HTTP for sensitive requests
- Verify you're connecting to official API endpoints
- Check SSL certificates are valid

### Responsible Use

- Use DataVault only for authorized security testing
- Respect rate limits and API terms of service
- Don't use this tool for unauthorized access or scanning
- Comply with all applicable laws and regulations

---

## Dependencies & Updates

Keep dependencies updated to patch security vulnerabilities:

```bash
pip install --upgrade -r requirements.txt
```

Check for known vulnerabilities:

```bash
pip install safety
safety check
```

---

## Disclaimer

This tool is provided for educational and authorized security testing only. Users are responsible for ensuring they have proper authorization before using this tool on any systems. Unauthorized access to computer systems is illegal.

---

## Contact

For security inquiries: **abuse@osintintelligence.xyz**

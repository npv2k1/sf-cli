# Security Policy

## Known Security Advisories

This document tracks known security advisories affecting SF-CLI and our mitigation strategies.

### Active Advisories

#### RUSTSEC-2023-0071: RSA Marvin Attack (Medium Severity - CVSS 5.9)

- **Affected Component**: `rsa` crate version 0.9.8
- **Issue**: Potential key recovery through timing side-channels in RSA decryption operations
- **Status**: ⚠️ No stable fix available (rsa 0.10 is still in RC)
- **Impact**: Theoretical timing side-channel attack during RSA decryption
- **Mitigation**: 
  - This vulnerability affects RSA private key operations in hybrid encryption mode
  - The attack requires precise timing measurements and is difficult to exploit in practice
  - Users concerned about this vulnerability should prefer using ECDSA keys (P-256) for hybrid encryption instead of RSA keys
  - We will update to rsa 0.10 once it reaches stable release
- **Reference**: https://rustsec.org/advisories/RUSTSEC-2023-0071

#### RUSTSEC-2024-0436: paste crate unmaintained

- **Affected Component**: `paste` crate version 1.0.15 (transitive dependency via ratatui 0.24.0)
- **Issue**: The paste crate is no longer maintained
- **Status**: ⚠️ Informational warning
- **Impact**: Low - paste is a proc-macro crate used only at compile time
- **Mitigation**: 
  - This is a transitive dependency through ratatui for the TUI interface
  - No runtime security impact as paste is only used during compilation
  - Will be resolved by updating ratatui to newer versions when stable releases are available
- **Reference**: https://rustsec.org/advisories/RUSTSEC-2024-0436

## Security Best Practices

When using SF-CLI, we recommend:

1. **Use strong passwords**: Always use strong, unique passwords for encryption
2. **Prefer ECDSA for hybrid encryption**: When using hybrid encryption mode, prefer ECDSA (P-256) keys over RSA keys
3. **Keep software updated**: Regularly update SF-CLI to get the latest security fixes
4. **Secure key storage**: Protect your SSH private keys with appropriate file permissions
5. **Verify checksums**: When downloading SF-CLI, verify the checksums match the official releases

## Reporting Security Issues

If you discover a security vulnerability in SF-CLI, please report it to:

- **Email**: (Add your security contact email)
- **GitHub Security Advisory**: Use GitHub's private security advisory feature

Please do not report security vulnerabilities through public GitHub issues.

## Supported Versions

We provide security updates for the latest stable release. Users are encouraged to upgrade to the latest version.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Acknowledgments

We thank the Rust security community and RustSec for maintaining the advisory database.

# Contributors

cfDr (Copy Fail Doctor) is built on the collective expertise and contributions of security professionals working to mitigate CVE-2026-31431.

## Core Contributors

### Paul Armstrong (@parmstro)
- **Role**: Project Lead & Primary Developer
- **Contributions**:
  - Initial project conception and implementation
  - Ansible role architecture and design
  - Module blacklist remediation
  - systemd seccomp integration
  - Bitwise flag system design
  - Project documentation and guides
  - Repository maintenance

### Anthony Green (@atgreen)
- **Role**: eBPF LSM Specialist
- **Contributions**:
  - Initial eBPF LSM mitigation implementation
  - BPF program design for socket_create hook
  - eBPF compilation and loading strategies
  - Kernel compatibility research
- **Project**: [Block-copyfail](https://github.com/atgreen/block-copyfail) - Original eBPF-based mitigation

### Greg Procunier (@gprocunier)
- **Role**: SELinux Security Expert
- **Contributions**:
  - Initial SELinux policy mitigation implementation
  - Policy module design and testing
  - SELinux domain configuration strategies
  - Enterprise Linux security hardening expertise
- **Project**: [Blastwall](https://gprocunier.github.io/blastwall/demo.html) - SELinux policy framework and tools

### Claude Sonnet 4.5 (AI Assistant)
- **Role**: Development Assistant
- **Contributions**:
  - Code generation and refactoring
  - Documentation writing
  - Alternative mitigation research
  - Testing strategies and best practices
  - Template and configuration file generation

## Acknowledgments

### Security Research Community
- **Xint.io** - Original CVE-2026-31431 discovery and disclosure
- **Theori** - Vulnerability analysis and proof-of-concept
- **Sysdig** - Comprehensive vulnerability documentation and analysis

### Linux Security Community
- SELinux maintainers and documentation authors
- eBPF/BPF LSM kernel developers
- systemd seccomp implementation team
- Ansible community for role development best practices

## How to Contribute

We welcome contributions from the security community! Areas where contributions are valuable:

### Code Contributions
- Additional mitigation strategies
- Platform-specific optimizations
- Testing and validation improvements
- Bug fixes and enhancements

### Documentation
- Translation to other languages
- Use case examples
- Troubleshooting guides
- Best practices documentation

### Testing
- Testing on different Linux distributions
- Edge case identification
- Performance benchmarking
- Integration testing

### Security Research
- Alternative mitigation approaches
- Bypass testing (responsible disclosure)
- Compatibility testing
- Performance impact analysis

## Contribution Process

1. **Fork** the repository: https://github.com/parmstro/cfDr
2. **Create** a feature branch: `git checkout -b feature/your-contribution`
3. **Commit** your changes with clear messages
4. **Test** thoroughly on multiple platforms
5. **Submit** a pull request with detailed description
6. **Engage** in code review process

## Attribution Guidelines

When contributing code or documentation:

- Maintain existing attribution in file headers
- Add your name to file-level contributors when making significant changes
- Update this CONTRIBUTORS.md file with your contribution
- Reference any external sources or prior art
- Follow the project's MIT license

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. All contributors are expected to:

- Be respectful and professional
- Focus on constructive feedback
- Acknowledge and learn from mistakes
- Prioritize security and user safety
- Follow responsible disclosure practices for vulnerabilities

## Contact

- **Issues**: https://github.com/parmstro/cfDr/issues
- **Pull Requests**: https://github.com/parmstro/cfDr/pulls
- **Discussions**: https://github.com/parmstro/cfDr/discussions

## Related Projects and Prior Art

### eBPF-based Mitigations
- **[Block-copyfail](https://github.com/atgreen/block-copyfail)** by Anthony Green
  - Original eBPF LSM implementation for CVE-2026-31431
  - Reference implementation for kernel-level socket blocking
  - Inspired the eBPF mitigation strategy in cfDr

### SELinux Tools and Frameworks
- **[Blastwall](https://gprocunier.github.io/blastwall/demo.html)** by Greg Procunier
  - SELinux policy framework and development tools
  - Enterprise security hardening methodologies
  - Reference for SELinux policy best practices

### Security Research
- **[Xint.io](https://xint.io)** - CVE-2026-31431 discovery and disclosure
- **[Theori](https://theori.io)** - Vulnerability analysis and proof-of-concept
- **[Sysdig](https://sysdig.com)** - Comprehensive vulnerability documentation

## License

All contributions to cfDr are made under the MIT License. By contributing, you agree that your contributions will be licensed under the same terms.

---

**Thank you to all contributors who help make systems more secure!** 🛡️

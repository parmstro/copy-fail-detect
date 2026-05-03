# cfDr Documentation Index

Complete documentation for cfDr - Copy Fail Detection and Remediation

---

## Getting Started

- **[README](../README.md)** - Main project documentation, quick start, and overview

---

## User Guides

### Playbook Usage

- **[Playbook Guide](PLAYBOOKS.md)** - Complete guide to using cfDr playbooks
- **[Role Usage](ROLE_USAGE.md)** - How to use the cve_2026_31431 role in your playbooks

### Recommended Workflow

See the [README - Recommended Workflow](../README.md#recommended-workflow) section for:
- Standard enterprise workflow
- Emergency response workflow  
- Continuous monitoring workflow
- Custom mitigation workflow

---

## Mitigation Guides

### Enterprise Linux Mitigations

- **[Enterprise Linux Mitigations](enterprise-linux-mitigations.md)** - Comprehensive comparison and deployment guide for RHEL/CentOS/Fedora

### Specific Mitigation Methods

- **[SELinux Mitigation](selinux-mitigation.md)** - SELinux policy implementation guide
- **[systemd seccomp Mitigation](seccomp-mitigation.md)** - systemd seccomp filter implementation guide
- **[eBPF LSM Mitigation](ebpf-lsm-mitigation.md)** - eBPF LSM program implementation guide (RHEL 9+)

### Protection Level Comparison

| Method | Can Root Bypass? | Coverage | Enterprise Linux Support | Complexity |
|--------|------------------|----------|-------------------------|------------|
| Module Blacklist | ✅ Yes (via insmod) | System-wide | All versions | Low |
| SELinux Policy | ❌ **NO** (LSM layer) | Configured domains | All versions | Medium |
| systemd seccomp | ❌ **NO** (syscall filter) | Configured services | All versions | Low |
| eBPF LSM | ❌ **NO** (LSM layer) | System-wide | RHEL 9+, Fedora 34+ | High |

**Recommended**: Flag 3 (Module Blacklist + SELinux) for defense-in-depth

---

## Development Documentation

### Change Logs and Bug Fixes

- **[Quiet Output and Flag 3 Changes](CHANGES_QUIET_OUTPUT_FLAG3.md)** - Changes to reduce verbose output and set Flag 3 as default
- **[Detection and Reporting Bug Fix](BUGFIX_DETECTION_REPORTING.md)** - Fix for multi-host detection issues
- **[Inventory Generation Bug Fix](BUGFIX_INVENTORY_GENERATION.md)** - Fix for inventory generation capturing only first host
- **[Ansible Best Practices Fixes](ANSIBLE_BEST_PRACTICES_FIXES.md)** - Ansible best practices and FQCN implementation

### Contributing

- **[Contributors Guide](CONTRIBUTORS.md)** - How to contribute to cfDr and contributor credits

---

## Quick Reference

### Mitigation Flags

| Flag | Mitigations | Use Case |
|------|------------|----------|
| 1 | Module Blacklist only | Minimal protection |
| 2 | SELinux only | SELinux-only environments |
| **3** | **Module Blacklist + SELinux** | **RECOMMENDED** |
| 5 | Module Blacklist + seccomp | Non-SELinux with services |
| 7 | Blacklist + SELinux + seccomp | Enhanced protection |
| 15 | All mitigations | Maximum (RHEL 9+ only) |

### Common Commands

**Assessment**:
```bash
ansible-playbook -i inventory quickstart.yml
```

**Remediation with recommended settings**:
```bash
ansible-playbook -i inventory quickstart.yml -e apply_remediation=true --limit vulnerable_hosts
```

**Generate vulnerability inventory**:
```bash
ansible-playbook -i inventory quickstart.yml -e generate_inventory=true
```

**Apply custom mitigation level**:
```bash
ansible-playbook -i inventory quickstart.yml -e apply_remediation=true -e mitigation_flags=7
```

---

## External Resources

### CVE Information

- [NVD - CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
- [Sysdig Analysis](https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds)
- [CERT-EU Advisory](https://cert.europa.eu/publications/security-advisories/2026-005/)

### Related Projects

- [block-copyfail](https://github.com/atgreen/block-copyfail) - eBPF LSM implementation by Anthony Green
- [Blastwall](https://gprocunier.github.io/blastwall/demo.html) - SELinux policy framework by Greg Procunier

### Red Hat Resources

- [Red Hat Customer Portal - CVE-2026-31431](https://access.redhat.com/security/cve/cve-2026-31431)
- [Security Updates](https://access.redhat.com/security/security-updates/)
- [Errata Advisories](https://access.redhat.com/errata/)

---

## Support

- **Issues**: [GitHub Issues](https://github.com/parmstro/cfDr/issues)
- **Discussions**: [GitHub Discussions](https://github.com/parmstro/cfDr/discussions)

---

**Last Updated**: 2026-05-02T23:45:00Z

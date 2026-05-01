
# CVE-2026-31431 (Copy Fail) Mitigation Role

Ansible role for detecting and mitigating CVE-2026-31431, a critical local privilege escalation vulnerability in the Linux kernel's algif_aead module.

## Overview

This role provides multi-layer protection against CVE-2026-31431 with flexible configuration via bitwise flags. It supports four distinct mitigation strategies that can be combined for defense-in-depth.

### Vulnerability Details

- **CVE ID**: CVE-2026-31431
- **Name**: Copy Fail
- **CVSS Score**: 7.8 (High)
- **Affected**: Linux kernels >= 4.10 (since ~2017)
- **Impact**: Local privilege escalation (unprivileged → root)
- **Component**: algif_aead module (AF_ALG userspace crypto API)

## Features

- ✅ **Bitwise flag-based mitigation control** - Enable/disable specific protections
- ✅ **Four mitigation strategies** - Module blacklist, SELinux, seccomp, eBPF LSM
- ✅ **Defense-in-depth** - Combine multiple layers for maximum protection
- ✅ **Comprehensive assessment** - Detect vulnerable systems
- ✅ **Detailed reporting** - JSON output and summary reports
- ✅ **Idempotent** - Safe to run multiple times
- ✅ **Enterprise Linux focused** - RHEL, CentOS, Fedora (also supports Ubuntu/Debian)

## Requirements

- Ansible 2.9 or higher
- Privileged access (sudo/root) on target hosts
- Supported distributions:
  - RHEL 8, 9
  - CentOS Stream 8, 9
  - AlmaLinux 8, 9
  - Rocky Linux 8, 9
  - Fedora 38+
  - Ubuntu 20.04, 22.04, 24.04
  - Debian 11, 12

## Role Variables

### Mitigation Control (Bitwise Flags)

The primary control mechanism uses bitwise flags to enable specific mitigations:

```yaml
# Mitigation flags (default: 7)
mitigation_flags: 7

# Flag values:
MITIGATE_MODULE_BLACKLIST: 1  # (0b0001) Blacklist algif_aead module
MITIGATE_SELINUX:          2  # (0b0010) SELinux policy
MITIGATE_SECCOMP:          4  # (0b0100) systemd seccomp
MITIGATE_EBPF_LSM:         8  # (0b1000) eBPF LSM (kernel 5.7+)
```

### Common Configurations

```yaml
# Assessment only (no remediation)
apply_remediation: false

# Module blacklist only
mitigation_flags: 1

# Module blacklist + SELinux (recommended minimum)
mitigation_flags: 3

# All except eBPF LSM (recommended for most systems)
mitigation_flags: 7

# All mitigations (for modern kernels)
mitigation_flags: 15
```

### Key Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `apply_remediation` | `false` | Apply remediations (true) or assess only (false) |
| `mitigation_flags` | `7` | Bitwise flags for mitigation selection |
| `perform_assessment` | `true` | Perform vulnerability assessment |
| `seccomp_protected_services` | See defaults | Services to harden with seccomp |
| `selinux_denied_domains` | See defaults | SELinux domains to deny AF_ALG access |

See `defaults/main.yml` for complete variable list.

## Mitigation Strategies

### 1. Module Blacklist (Flag: 1)

**How it works:**
- Blacklists algif_aead kernel module via `/etc/modprobe.d/`
- Prevents `modprobe` loading
- Updates initramfs/initrd for boot persistence

**Protection:**
- ✅ Blocks automatic module loading
- ✅ Blocks `modprobe algif_aead`
- ✅ Persists across reboots
- ❌ Can be bypassed with `insmod` (root required)

**When to use:** Always - baseline protection for all systems

### 2. SELinux Policy (Flag: 2)

**How it works:**
- Installs SELinux policy module that denies AF_ALG socket creation
- Blocks at kernel LSM layer
- System-wide enforcement

**Protection:**
- ✅ Blocks socket creation even if module is loaded
- ✅ Cannot be bypassed from userspace
- ✅ Provides audit trail
- ✅ Works with module blacklist for defense-in-depth

**When to use:** Primary mitigation for RHEL/CentOS/Fedora (default LSM)

**Requirements:** SELinux in Enforcing mode

### 3. systemd seccomp (Flag: 4)

**How it works:**
- Adds `RestrictAddressFamilies=~AF_ALG` to systemd service units
- Per-service syscall filtering
- Blocks AF_ALG socket creation via seccomp-bpf

**Protection:**
- ✅ Per-service isolation
- ✅ Minimal overhead
- ✅ Works without SELinux
- ❌ Only protects systemd services

**When to use:** Harden critical services (httpd, postgresql, etc.)

**Requirements:** systemd as service manager

### 4. eBPF LSM (Flag: 8)

**How it works:**
- Loads eBPF program that hooks into LSM socket_create
- Dynamic, programmable kernel-level enforcement
- System-wide blocking

**Protection:**
- ✅ Very flexible and powerful
- ✅ System-wide enforcement
- ✅ Real-time updates
- ✅ Built-in observability

**When to use:** Modern kernels (RHEL 9, Fedora 38+) with advanced requirements

**Requirements:**
- Kernel 5.7+
- CONFIG_BPF_LSM=y
- `lsm=...,bpf` boot parameter

## Usage

### Basic Usage - Assessment Only

```yaml
- hosts: all
  become: true
  roles:
    - role: cve_2026_31431
      vars:
        apply_remediation: false
```

### Apply Module Blacklist Only

```yaml
- hosts: all
  become: true
  roles:
    - role: cve_2026_31431
      vars:
        apply_remediation: true
        mitigation_flags: 1
```

### Recommended Configuration (RHEL/CentOS/Fedora)

```yaml
- hosts: all
  become: true
  roles:
    - role: cve_2026_31431
      vars:
        apply_remediation: true
        mitigation_flags: 7  # Module blacklist + SELinux + seccomp
```

### Maximum Protection (Modern Kernels)

```yaml
- hosts: all
  become: true
  roles:
    - role: cve_2026_31431
      vars:
        apply_remediation: true
        mitigation_flags: 15  # All mitigations
```

### Target Specific Services for seccomp

```yaml
- hosts: webservers
  become: true
  roles:
    - role: cve_2026_31431
      vars:
        apply_remediation: true
        mitigation_flags: 4  # seccomp only
        seccomp_protected_services:
          - httpd
          - nginx
```

## Example Playbook

See `cve_2026_31431_playbook.yml` for a complete example with summary reporting.

```yaml
---
- name: CVE-2026-31431 Mitigation
  hosts: all
  become: true
  gather_facts: true
  vars:
    apply_remediation: true
    mitigation_flags: 7
  roles:
    - cve_2026_31431
```

Run it:

```bash
# Assessment only
ansible-playbook cve_2026_31431_playbook.yml

# Apply module blacklist + SELinux + seccomp
ansible-playbook cve_2026_31431_playbook.yml -e apply_remediation=true -e mitigation_flags=7

# Target only vulnerable hosts
ansible-playbook cve_2026_31431_playbook.yml -e apply_remediation=true --limit vulnerable_hosts
```

## Tags

Control execution with tags:

```bash
# Run only assessment
ansible-playbook playbook.yml --tags assessment

# Run only SELinux remediation
ansible-playbook playbook.yml --tags selinux

# Skip eBPF
ansible-playbook playbook.yml --skip-tags ebpf
```

Available tags:
- `always` - Always runs (preflight, assessment)
- `assessment` - Vulnerability assessment
- `remediation` - All remediations
- `module-blacklist` - Module blacklist remediation
- `selinux` - SELinux policy remediation
- `seccomp` - systemd seccomp remediation
- `ebpf` - eBPF LSM remediation
- `reporting` - Report generation
- `cleanup` - Remove remediations (use with `--tags cleanup`)

## Defense-in-Depth Strategy

**Recommended layered approach:**

```
┌───────────────────────────────────────┐
│  Layer 1: SELinux (syscall blocking)  │  ← Primary defense
├───────────────────────────────────────┤
│  Layer 2: Module Blacklist            │  ← Prevents loading
├───────────────────────────────────────┤
│  Layer 3: systemd seccomp             │  ← Service hardening
└───────────────────────────────────────┘
```

**Why multiple layers?**

| Scenario | Module Blacklist | SELinux | seccomp | Result |
|----------|------------------|---------|---------|--------|
| Normal attack | ✅ Blocks | ✅ Blocks | ✅ Blocks | Protected |
| SELinux disabled | ✅ Blocks | ❌ Bypassed | ✅ Blocks | Protected |
| Root with insmod | ❌ Bypassed | ✅ Blocks | ✅ Blocks | Protected |

## Verification

### Check Applied Mitigations

```bash
# Module blacklist
cat /etc/modprobe.d/blacklist-algif_aead-cve-2026-31431.conf
modprobe algif_aead  # Should fail

# SELinux policy
semodule -l | grep cve_2026_31431
ausearch -m avc | grep alg_socket

# systemd seccomp
systemctl show httpd | grep RestrictAddressFamilies

# eBPF LSM
bpftool prog list
cat /sys/kernel/debug/tracing/trace_pipe | grep AF_ALG
```

### Test Protection

```python
# This should fail with PermissionError if protected
python3 -c "import socket; socket.socket(38, 2, 0)"
```

## Reporting

The role generates:
- **JSON reports**: `/tmp/cve-2026-31431-{hostname}.json`
- **Summary report**: Displayed at playbook end
- **Per-host assessment**: Detailed vulnerability status

## Cleanup

To remove all remediations:

```bash
ansible-playbook playbook.yml -e remove_remediations=true --tags cleanup
```

**WARNING:** This removes all protection and makes systems vulnerable again.

## Troubleshooting

### SELinux policy won't install

```bash
# Check SELinux status
getenforce

# Verify packages
rpm -q policycoreutils policycoreutils-python-utils selinux-policy-devel
```

### eBPF LSM not available

```bash
# Check kernel version
uname -r  # Need >= 5.7

# Check CONFIG_BPF_LSM
grep CONFIG_BPF_LSM /boot/config-$(uname -r)

# Check if BPF LSM is active
cat /sys/kernel/security/lsm
```

### seccomp breaks service

Check service logs and adjust `seccomp_protected_services` list.

## License

MIT

## Authors and Contributors

- **Paul Armstrong** (@parmstro) - Project Lead, Role Architecture, Module Blacklist & seccomp
- **Anthony Green** (@atgreen) - Initial eBPF LSM mitigation implementation
- **Greg Procunier** (@gprocunier) - Initial SELinux policy mitigation implementation
- **Claude Sonnet 4.5** - Development assistance, documentation, and research

See [CONTRIBUTORS.md](../../CONTRIBUTORS.md) for complete details and how to contribute.

## References

- [Sysdig CVE-2026-31431 Analysis](https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds)
- [The Hacker News - Copy Fail](https://thehackernews.com/2026/04/new-linux-copy-fail-vulnerability.html)
- [CERT-EU Advisory](https://cert.europa.eu/publications/security-advisories/2026-005/)

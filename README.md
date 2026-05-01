# CVE-2026-31431 (Copy Fail) Detection and Remediation Playbook

This Ansible playbook detects and remediates CVE-2026-31431, a critical local privilege escalation vulnerability in the Linux kernel's algif_aead module.

## Overview

**CVE-2026-31431** (CVSS 7.8) is a logic flaw in the Linux kernel's AEAD socket interface (AF_ALG) that allows any unprivileged local user to escalate to root privileges. The vulnerability affects kernels released since 2017 (kernel >= 4.10).

## Quick Start

### 1. Assessment Only (Default)
Run the playbook to scan all hosts and identify vulnerable systems:

```bash
ansible-playbook check_af_alg.yml
```

### 2. Remediate All Vulnerable Hosts
Apply the mitigation to all vulnerable hosts identified:

```bash
ansible-playbook check_af_alg.yml -e apply_remediation=true --limit vulnerable_hosts
```

### 3. Remediate Specific Hosts
Apply remediation to specific hosts:

```bash
ansible-playbook check_af_alg.yml -e apply_remediation=true --limit "host1,host2"
```

## Playbook Features

### Detection
The playbook performs comprehensive vulnerability assessment:

- ✅ Kernel version check (vulnerable range: >= 4.10)
- ✅ algif_aead module availability check
- ✅ Current module load status
- ✅ Active AF_ALG socket detection
- ✅ Existing mitigation verification
- ✅ Categorical vulnerability status determination

### Remediation

#### What It Does
1. **Unloads** the algif_aead module if currently loaded
2. **Creates** blacklist configuration in `/etc/modprobe.d/`
3. **Updates** initramfs/initrd to persist across reboots
4. **Verifies** successful remediation

#### Configuration Created
```
/etc/modprobe.d/blacklist-algif_aead-cve-2026-31431.conf
```

### Vulnerability Status Categories

| Status | Description |
|--------|-------------|
| **VULNERABLE - Module loaded** | Actively exploitable, immediate action required |
| **VULNERABLE - Module exists** | Can be loaded and exploited, remediation recommended |
| **MITIGATED - Blacklisted** | Module is blacklisted, vulnerability mitigated |
| **NOT VULNERABLE - Old kernel** | Kernel version predates vulnerability (< 4.10) |
| **NOT VULNERABLE - No module** | algif_aead module not available in kernel |

## Remediation Details

### Recommended Remediation
**Blacklist the algif_aead kernel module**

### Description

This remediation creates a modprobe blacklist configuration that prevents the algif_aead kernel module from being loaded. The blacklist uses two mechanisms:

1. **`blacklist algif_aead`** - Prevents automatic module loading (hardware detection, udev rules, etc.)
2. **`install algif_aead /bin/true`** - Intercepts explicit `modprobe` commands and runs `/bin/true` instead

The blacklist configuration is added to `/etc/modprobe.d/` and the initramfs/initrd is updated so the protection persists across reboots.

### How It Works

**Immediate Protection (No Reboot):**
- Currently loaded module is unloaded with `rmmod`
- Blacklist prevents immediate re-loading
- Effective within seconds

**Persistent Protection (After Reboot):**
- Updated initramfs/initrd contains the blacklist
- Module won't load during boot process
- Protection survives kernel updates that preserve initramfs

### Protection Scope

| Attack Vector | Protected? | Mechanism |
|---------------|------------|-----------|
| `modprobe algif_aead` | ✅ Yes | `install` directive intercepts and runs `/bin/true` |
| Auto-loading via dependencies | ✅ Yes | `install` directive handles dependency resolution |
| Module loading at boot | ✅ Yes | Blacklist embedded in initramfs/initrd |
| Kernel module auto-probing | ✅ Yes | `blacklist` directive prevents auto-load |
| `insmod /path/to/algif_aead.ko` | ❌ **NO** | Direct kernel insertion bypasses modprobe |
| Root decompressing .ko.xz and loading | ❌ **NO** | Kernel doesn't enforce blacklists at this level |

### Limitations

**Important Security Note:** This remediation protects against the typical CVE-2026-31431 attack chain (unprivileged user → load module → exploit → root), but a **root user with malicious intent** can bypass the blacklist using:

```bash
# Blacklist does NOT prevent:
insmod /lib/modules/$(uname -r)/kernel/crypto/algif_aead.ko.xz

# Or after decompression:
insmod /tmp/algif_aead.ko
```

**Why this is acceptable:** The vulnerability requires **local code execution** to exploit. If an attacker already has root access, they can already run the exploit directly or load the module via `insmod`. The blacklist prevents **privilege escalation** from unprivileged → root, which is the primary attack vector.

### Implications

#### ✓ Positive Effects
- **Mitigates CVE-2026-31431** for standard attack vectors
- **No reboot required** - protection active immediately
- **Persists across reboots** and kernel updates
- **Handles module dependencies** - dependent modules can't force-load algif_aead
- **Reversible** - can be undone if needed

#### ⚠ Cautions
- **Root users can bypass** via `insmod` (requires insider threat model)
- **Applications using AF_ALG AEAD crypto** may fail (very rare)
- Does **not** affect standard system crypto operations (SSL/TLS, SSH, etc.)
- This is a **temporary workaround** - kernel patches are the permanent fix
- **Dependent modules**: Any module depending on algif_aead will fail to load

### When to Apply

| Scenario | Recommendation |
|----------|----------------|
| Production servers | Apply immediately after testing |
| Development systems | Apply with caution, test applications first |
| Systems with custom crypto | Verify no AF_ALG usage before applying |
| Critical infrastructure | Apply immediately, monitor for issues |

## Advanced Security Measures

If you require protection against malicious root users or insider threats who could bypass the modprobe blacklist, consider these additional hardening measures:

### 1. Remove Module File (Most Effective)
```bash
# Backup the module
cp /lib/modules/$(uname -r)/kernel/crypto/algif_aead.ko.xz /root/backup/

# Remove the module file
rm /lib/modules/$(uname -r)/kernel/crypto/algif_aead.ko.xz

# Update module dependencies
depmod -a
```

**Pros:** Module cannot be loaded by any method  
**Cons:** May break if kernel is reinstalled; requires restoration if needed

### 2. SELinux Policy (RECOMMENDED for Enterprise Linux)
For RHEL/CentOS/Fedora systems, SELinux can block AF_ALG socket creation at the syscall level - preventing exploitation even if the module is loaded.

**See [selinux-mitigation.md](selinux-mitigation.md) for complete implementation guide**

**Pros:** Default on RHEL/CentOS/Fedora; blocks at LSM layer; cannot be bypassed  
**Cons:** Requires SELinux in Enforcing mode; some policy knowledge helpful

### 3. Kernel Module Signing with Lockdown
Enable kernel module signature enforcement:

```bash
# Only allow signed modules (requires UEFI Secure Boot)
# Set in kernel parameters: module.sig_enforce=1
```

**Pros:** Prevents loading of any unsigned/modified modules  
**Cons:** Requires complete module signing infrastructure

### 4. Monitoring and Alerting
Monitor for module loading attempts:

```bash
# Audit rule to detect module loading
auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -F key=module_insertion

# Monitor audit log
ausearch -k module_insertion --start today
```

**Pros:** Detects bypass attempts  
**Cons:** Reactive, not preventive

### 5. systemd seccomp Restrictions
For individual services, systemd can block AF_ALG socket creation via seccomp filters:

**See [seccomp-mitigation.md](seccomp-mitigation.md) for implementation guide**

```ini
# Add to service unit files:
[Service]
RestrictAddressFamilies=~AF_ALG
```

**Pros:** Simple systemd directive; per-service control; works without SELinux  
**Cons:** Per-service configuration needed; only protects systemd services

### 6. eBPF LSM (RHEL 9+ / Fedora)
For modern kernels (5.7+), eBPF LSM programs can provide dynamic, programmable security policies:

**See [ebpf-lsm-mitigation.md](ebpf-lsm-mitigation.md) for implementation guide**

**Pros:** Very flexible; system-wide; real-time updates  
**Cons:** Requires modern kernel; higher complexity; requires setup

## Alternative Mitigation Strategies

This playbook implements **module blacklisting** as the baseline mitigation. For Enterprise Linux environments (RHEL, CentOS, Fedora), several alternative or complementary approaches are available:

| Method | Complexity | Enterprise Linux Support | Recommended |
|--------|------------|-------------------------|-------------|
| **Module Blacklist** | Low | ✅ All versions | ✅ Baseline |
| **SELinux Policy** | Medium | ✅ All versions (default) | ✅ **PRIMARY** |
| **systemd seccomp** | Low | ✅ All versions | ✅ Per-service |
| **eBPF LSM** | High | RHEL 9+, Fedora 34+ | ⚠️ Advanced |

### For Complete Enterprise Linux Guidance:

📘 **[enterprise-linux-mitigations.md](enterprise-linux-mitigations.md)** - Comprehensive comparison and deployment guide for RHEL/CentOS/Fedora environments

**Key Recommendations:**
1. **RHEL 8/9**: Deploy SELinux policy as primary defense + module blacklist as backup
2. **Critical Services**: Add systemd seccomp restrictions for defense-in-depth
3. **Modern Systems**: Consider eBPF LSM for advanced use cases (RHEL 9+ only)

### Defense-in-Depth Strategy

**Best Practice: Use multiple layers**

```
┌─────────────────────────────────────┐
│  Layer 1: SELinux (syscall blocking) │  ← Primary defense
├─────────────────────────────────────┤
│  Layer 2: Module Blacklist          │  ← Prevents modprobe loading
├─────────────────────────────────────┤
│  Layer 3: systemd seccomp           │  ← Service-level hardening
└─────────────────────────────────────┘
```

If any layer is bypassed, the others still provide protection.

## Output and Reporting

### Per-Host Assessment
Each host displays:
- Kernel version
- Vulnerability status
- Detailed check results
- Remediation recommendations

### JSON Reports
Individual assessment reports saved to:
```
/tmp/cve-2026-31431-{hostname}.json
```

### Summary Report
- Total hosts scanned
- Vulnerable hosts count and list
- Remediated hosts count (if applicable)
- Command to remediate vulnerable hosts

## Workflow Examples

### Example 1: Initial Assessment
```bash
# Scan all hosts
ansible-playbook check_af_alg.yml

# Review output for vulnerable hosts
# Example output:
# Vulnerable hosts: 3
# Vulnerable hosts: webserver1, dbserver2, appserver3
```

### Example 2: Targeted Remediation
```bash
# Remediate only vulnerable hosts
ansible-playbook check_af_alg.yml -e apply_remediation=true --limit vulnerable_hosts

# Verify remediation
ansible-playbook check_af_alg.yml --limit vulnerable_hosts
```

### Example 3: Emergency Response
```bash
# Scan and immediately remediate all vulnerable hosts
ansible-playbook check_af_alg.yml -e apply_remediation=true
```

## Verification

After remediation, verify the mitigation:

```bash
# On the remediated host:
sudo lsmod | grep algif_aead
# Should return nothing (module not loaded)

sudo modprobe algif_aead
# Should fail with error (module blacklisted)

cat /etc/modprobe.d/blacklist-algif_aead-cve-2026-31431.conf
# Should show blacklist configuration
```

## Rollback

To remove the remediation (if needed):

```bash
# Remove blacklist file
sudo rm /etc/modprobe.d/blacklist-algif_aead-cve-2026-31431.conf

# Update initramfs (Debian/Ubuntu)
sudo update-initramfs -u

# Update initrd (RedHat/Fedora)
sudo dracut -f

# Module can now be loaded again
sudo modprobe algif_aead
```

## Next Steps

1. **Immediate**: Apply remediation to vulnerable hosts
2. **Short-term**: Monitor vendor security advisories
3. **Long-term**: Update to patched kernel version when available
4. **Ongoing**: Re-scan regularly for new systems

## Requirements

- Ansible 2.9 or higher
- Privileged access (sudo/root) on target hosts
- Supported distributions: RedHat, CentOS, Fedora, Debian, Ubuntu, SUSE

## References

- [Sysdig - CVE-2026-31431 Analysis](https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds)
- [The Hacker News - Copy Fail Vulnerability](https://thehackernews.com/2026/04/new-linux-copy-fail-vulnerability.html)
- [CERT-EU Security Advisory](https://cert.europa.eu/publications/security-advisories/2026-005/)
- [Help Net Security - Copy Fail Details](https://www.helpnetsecurity.com/2026/04/30/copyfail-linux-lpe-vulnerability-cve-2026-31431/)

## Support

For issues or questions about this playbook, review the output logs and JSON reports generated in `/tmp/`.

## License

This playbook is provided as-is for vulnerability assessment and remediation purposes.

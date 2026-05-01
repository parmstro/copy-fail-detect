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
This remediation prevents the vulnerable algif_aead module from being loaded into the kernel, effectively mitigating CVE-2026-31431. The module is unloaded if currently active and blacklisted to prevent future loading.

### Implications

#### ✓ Positive Effects
- **Eliminates** local privilege escalation vector
- **No reboot required** - effective immediately
- **Persists across reboots** via blacklist configuration
- **Reversible** - can be undone if needed

#### ⚠ Cautions
- Applications using AF_ALG AEAD crypto operations may fail
- Rarely affects production systems (algif_aead is infrequently used)
- Does **not** affect standard system crypto operations (SSL/TLS, SSH, etc.)
- This is a **temporary workaround** - kernel patches are the permanent fix

### When to Apply

| Scenario | Recommendation |
|----------|----------------|
| Production servers | Apply immediately after testing |
| Development systems | Apply with caution, test applications first |
| Systems with custom crypto | Verify no AF_ALG usage before applying |
| Critical infrastructure | Apply immediately, monitor for issues |

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

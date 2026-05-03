# cfDr - Copy Fail Doctor

**C**opy **F**ail **D**etection and **R**emediation

An Ansible role and playbook suite for detecting and remediating CVE-2026-31431 (Copy Fail), a critical local privilege escalation vulnerability in the Linux kernel's algif_aead module.

## Repository

🔗 **GitHub**: https://github.com/parmstro/cfDr

The name **cfDr** is a play on "Copy Fail Doctor" - your trusted remedy for CVE-2026-31431.

---

## Table of Contents

1. [Understanding CVE-2026-31431](#understanding-cve-2026-31431)
2. [Available Remediations](#available-remediations)
3. [Detection Methodology](#detection-methodology)
4. [How cfDr Works](#how-cfdr-works)
5. [Recommended Workflow](#recommended-workflow)
6. [Additional Resources](#additional-resources)
7. [Monitoring for Patches](#monitoring-for-patches)
8. [Quick Start](#quick-start)
9. [Advanced Configuration](#advanced-configuration)

---

## Understanding CVE-2026-31431

### What is Copy Fail?

**CVE-2026-31431** (CVSS 7.8) is a logic flaw in the Linux kernel's AEAD socket interface (AF_ALG) discovered in 2026. The vulnerability allows any unprivileged local user to escalate privileges to root in seconds.

### Technical Details

- **Affected Component**: `algif_aead` kernel module (AF_ALG crypto interface)
- **Vulnerability Type**: Logic flaw in copy operation handling
- **Attack Vector**: Local
- **Privileges Required**: None (unprivileged user)
- **User Interaction**: None
- **Impact**: Complete system compromise (root access)

### Affected Systems

**Kernel Versions**: Linux kernel >= 4.10 (released 2017)

**Distributions Affected**:
- Red Hat Enterprise Linux 7, 8, 9
- CentOS 7, 8, 9 (and Stream)
- Fedora (all currently supported versions)
- Ubuntu 17.04 and later
- Debian 9 (Stretch) and later
- SUSE Linux Enterprise 12, 15

**Note**: Any Linux distribution with kernel 4.10 or newer is potentially vulnerable.

### Why This Matters

This vulnerability is particularly dangerous because:

1. **No privileges required** - Any user account can exploit it
2. **Instant escalation** - Root access in seconds
3. **Widespread impact** - Affects 7+ years of kernel releases
4. **Local execution** - No remote access needed, but attackers who gain initial foothold can immediately escalate
5. **Active exploitation** - Public exploits are available

### Real-World Impact

Once an attacker has any form of local access (SSH, web shell, container escape, etc.), they can:
- Gain complete control of the system
- Install persistent backdoors
- Access sensitive data
- Pivot to other systems on the network
- Deploy ransomware or cryptominers

---

## Available Remediations

While waiting for vendor-supplied kernel patches, several mitigation strategies are available. **cfDr** implements all of them, with intelligent recommendations based on your system configuration.

### Understanding Protection Levels

Not all remediations are equal. Here's what you need to know:

| Method | Can Root Bypass? | Coverage | Enterprise Linux Support |
|--------|------------------|----------|-------------------------|
| **Module Blacklist** | ✅ Yes (via insmod) | Prevents modprobe loading | All versions |
| **SELinux Policy** | ❌ **NO** (LSM layer) | Configured domains only | All versions (default) |
| **systemd seccomp** | ❌ **NO** (syscall filter) | Configured services only | All versions |
| **eBPF LSM** | ❌ **NO** (LSM layer) | System-wide (if configured) | RHEL 9+, Fedora 34+ |

### Recommended Approach: Defense-in-Depth

**cfDr's default recommendation: Flag 3** (Module Blacklist + SELinux)

This provides **two independent protection layers**:

```
┌─────────────────────────────────────────────────┐
│  Layer 1: Module Blacklist                      │
│  • Prevents modprobe algif_aead                 │
│  • Persists across reboots                      │
│  • CAN be bypassed by malicious root (insmod)   │
├─────────────────────────────────────────────────┤
│  Layer 2: SELinux Policy                        │
│  • Blocks AF_ALG socket() at syscall level      │
│  • Works even if module is loaded               │
│  • CANNOT be bypassed from userspace            │
│  • Covers user_t, unconfined_t (majority cases) │
└─────────────────────────────────────────────────┘

Result: If either layer fails, the other still protects
```

### Why Module Blacklist Alone Is Not Enough

A determined attacker with root access can bypass module blacklisting:

```bash
# Module blacklist DOES NOT prevent:
insmod /lib/modules/$(uname -r)/kernel/crypto/algif_aead.ko.xz
```

**However**, this is acceptable because:
1. The vulnerability targets **privilege escalation** (unprivileged → root)
2. If an attacker already has root, they can exploit directly without loading the module
3. Module blacklist protects against **the primary attack vector**

### Complete Protection Strategy

For **complete, non-bypassable protection**, you need:

**Module Blacklist + at least one of:**
- SELinux policy (recommended for Enterprise Linux)
- systemd seccomp filters (per-service protection)
- eBPF LSM program (RHEL 9+ only, system-wide)

### Mitigation Flag Reference

cfDr uses bitwise flags to enable multiple mitigations:

| Flag Value | Mitigations Enabled | Use Case |
|------------|-------------------|----------|
| 1 | Module Blacklist only | Minimal protection, systems without SELinux |
| 2 | SELinux only | SELinux-only environments |
| **3** | **Module Blacklist + SELinux** | **RECOMMENDED default** |
| 5 | Module Blacklist + seccomp | Non-SELinux with service hardening |
| 7 | Module Blacklist + SELinux + seccomp | Enhanced protection |
| 15 | All mitigations | Maximum protection (RHEL 9+ only) |

**Calculate flags**: 1 (blacklist) + 2 (SELinux) + 4 (seccomp) + 8 (eBPF) = sum

### Coverage Gaps to Be Aware Of

**SELinux Protection**:
- Only covers domains specified in the policy: `user_t`, `unconfined_t`, `httpd_t`, `postgresql_t`, `mysqld_t`
- Processes running in other SELinux domains may not be protected
- In practice, `user_t` and `unconfined_t` cover the vast majority of attack scenarios

**systemd seccomp Protection**:
- Only protects services explicitly configured
- Default configuration covers: `httpd`, `nginx`, `postgresql`, `mariadb`, `redis`, `memcached`
- Processes outside these services are not protected

**eBPF LSM Protection**:
- Requires kernel 5.7+ (RHEL 9, Fedora 34+)
- Complexity requires expertise to implement correctly
- Can provide comprehensive system-wide protection if configured properly

---

## Detection Methodology

### How cfDr Detects Vulnerability

cfDr performs comprehensive assessment across multiple dimensions:

#### 1. Kernel Version Check
```bash
uname -r
```
- Determines if kernel version >= 4.10 (vulnerable range)
- Identifies kernel release and distribution

#### 2. Module Availability Check
```bash
modinfo algif_aead
```
- Verifies if `algif_aead` module exists in the kernel
- Checks module location and metadata

#### 3. Module Load Status
```bash
lsmod | grep algif_aead
```
- Determines if module is currently loaded
- **Critical**: Loaded module = actively exploitable

#### 4. Active Socket Detection
```bash
lsof -U | grep AF_ALG
```
- Identifies active AF_ALG sockets
- Indicates potential active exploitation

#### 5. Existing Mitigation Detection

**Module Blacklist**:
```bash
grep -E "blacklist algif_aead|install algif_aead" /etc/modprobe.d/*.conf
```

**SELinux Policy**:
```bash
semodule -l | grep cve_2026_31431_af_alg_deny
```

**systemd seccomp**:
```bash
systemctl show <service> | grep RestrictAddressFamilies
```

#### 6. Categorical Status Determination

cfDr categorizes each host into one of these states:

| Status | Condition | Action Required |
|--------|-----------|-----------------|
| **VULNERABLE - Module loaded** | Kernel >= 4.10, module exists AND loaded | **IMMEDIATE** - Actively exploitable |
| **VULNERABLE - Module exists** | Kernel >= 4.10, module exists, not loaded | **HIGH** - Can be loaded and exploited |
| **MITIGATED - Module blacklisted** | Blacklist detected | **LOW** - Monitor, apply additional layers |
| **PROTECTED - Defense-in-depth** | Blacklist + SELinux/seccomp/eBPF | **NONE** - Fully protected |
| **NOT VULNERABLE - Old kernel** | Kernel < 4.10 | **NONE** - Predates vulnerability |
| **NOT VULNERABLE - No module** | algif_aead module not in kernel | **NONE** - Module not available |

### Assessment Output

Each host receives:
1. **Console output**: Brief one-line status
2. **Detailed file**: `/root/cve-2026-31431-assessment-<hostname>.txt`
3. **JSON report**: `/tmp/cve-2026-31431-<hostname>.json`

Example brief output:
```
webserver1.example.com: VULNERABLE - Module exists and can be loaded
dbserver2.example.com: PROTECTED - Defense-in-depth (Module Blacklist + SELinux)
appserver3.example.com: NOT VULNERABLE - Module not available
```

---

## How cfDr Works

### Architecture

cfDr is built as a modern Ansible role with multiple playbook entry points:

```
cfDr/
├── roles/
│   └── cve_2026_31431/           # Main role
│       ├── tasks/
│       │   ├── main.yml           # Role orchestration
│       │   ├── assessment.yml     # Vulnerability detection
│       │   ├── remediation_module_blacklist.yml
│       │   ├── remediation_selinux.yml
│       │   ├── remediation_seccomp.yml
│       │   ├── remediation_ebpf.yml
│       │   ├── reporting.yml      # Status reporting
│       │   └── inventory_update.yml  # Inventory generation
│       ├── templates/             # Config file templates
│       ├── defaults/              # Default variables
│       └── handlers/              # Service restarts, etc.
├── quickstart.yml                 # Simplest usage
├── sample_playbook.yml            # Multiple examples
└── cve_2026_31431_playbook.yml   # Full-featured playbook
```

### Execution Flow

#### Assessment Mode (default)
```
1. Pre-flight checks
   ↓
2. Gather system facts
   ↓
3. Detect kernel version
   ↓
4. Check module availability
   ↓
5. Check current load status
   ↓
6. Check existing mitigations
   ↓
7. Determine vulnerability status
   ↓
8. Flag vulnerable hosts
   ↓
9. Generate reports
   ↓
10. Create summary
   ↓
11. [Optional] Generate inventory
```

#### Remediation Mode (`apply_remediation=true`)
```
1-8. [Same as Assessment Mode]
   ↓
9. Apply Module Blacklist (if flag 1)
   • Unload module if loaded
   • Create blacklist config
   • Update initramfs/initrd
   • Verify blacklist works
   ↓
10. Apply SELinux Policy (if flag 2)
    • Install policy packages
    • Compile policy module
    • Install policy
    • Verify policy active
   ↓
11. Apply systemd seccomp (if flag 4)
    • Create drop-in files
    • Reload systemd
    • Restart services
    • Verify filters active
   ↓
12. Apply eBPF LSM (if flag 8)
    • Compile eBPF program
    • Load into kernel
    • Verify program attached
   ↓
13. Re-assess protection status
   ↓
14. Generate reports
   ↓
15. Create summary
```

### Remediation Details

#### Module Blacklist (Flag 1)

**What it does**:
1. Unloads `algif_aead` module if currently loaded (`rmmod algif_aead`)
2. Creates `/etc/modprobe.d/blacklist-algif_aead-cve-2026-31431.conf`:
   ```
   blacklist algif_aead
   install algif_aead /bin/true
   ```
3. Updates initramfs/initrd to persist across reboots:
   - **Debian/Ubuntu**: `update-initramfs -u`
   - **RHEL/Fedora**: `dracut -f`
4. Verifies module cannot be loaded via `modprobe`

**Protection**: Immediate, no reboot required
**Persistence**: Survives reboots and kernel updates

#### SELinux Policy (Flag 2)

**What it does**:
1. Installs required packages:
   - `policycoreutils`
   - `policycoreutils-python-utils`
   - `selinux-policy-devel`
   - `checkpolicy`
2. Creates SELinux policy module denying AF_ALG socket creation
3. Compiles policy using SELinux build system
4. Installs policy module: `semodule -i cve_2026_31431_af_alg_deny.pp`
5. Verifies policy is active

**Domains protected** (default):
- `user_t` - Regular user processes
- `unconfined_t` - Unconfined processes
- `httpd_t` - Apache web server
- `postgresql_t` - PostgreSQL database
- `mysqld_t` - MySQL/MariaDB database

**Protection**: Blocks at LSM layer, cannot be bypassed
**Persistence**: Policy survives reboots

#### systemd seccomp (Flag 4)

**What it does**:
1. Creates systemd drop-in files: `/etc/systemd/system/<service>.service.d/90-cve-2026-31431-block-af-alg.conf`
2. Adds `RestrictAddressFamilies=~AF_ALG` directive
3. Reloads systemd daemon
4. Restarts affected services
5. Verifies filters are active

**Services protected** (default):
- `httpd`, `nginx` - Web servers
- `postgresql`, `mariadb` - Databases
- `redis`, `memcached` - Cache servers

**Protection**: Blocks socket creation at syscall level per service
**Persistence**: Survives reboots and service updates

#### eBPF LSM (Flag 8)

**What it does**:
1. Compiles eBPF program to block AF_ALG socket creation
2. Loads program into kernel
3. Attaches to LSM hooks
4. Verifies program is active

**Requirements**:
- Kernel 5.7+ with `CONFIG_BPF_LSM=y`
- RHEL 9, Fedora 34+, or custom compiled kernel

**Protection**: Dynamic, programmable system-wide policy
**Persistence**: Requires system service to reload on boot

### Inventory Generation

cfDr can generate ready-to-use inventory files containing only vulnerable hosts:

**Generated files**:
```
inventory_output/
├── vulnerable_hosts.yml          # YAML inventory
├── vulnerable_hosts.ini          # INI inventory
├── group_vars_vulnerable_hosts.yml  # Group variables
└── host_vars/
    ├── host1.yml                 # Per-host details
    └── host2.yml
```

**What's included**:
- Vulnerability assessment results
- Recommended mitigation flags (calculated per host)
- System details (kernel version, SELinux status)
- Ready-to-apply remediation settings

**Intelligent recommendations**:
- Flag 3 (Module Blacklist + SELinux) if SELinux is enabled
- Flag 1 (Module Blacklist only) if SELinux is not available
- Customizable per host via generated `host_vars`

---

## Recommended Workflow

### Standard Enterprise Workflow

This workflow balances thoroughness with operational safety:

#### Step 1: Initial Assessment (Read-Only)

```bash
# Scan all hosts without making changes
ansible-playbook -i inventory quickstart.yml
```

**What happens**:
- All hosts are assessed
- No changes are made
- Reports are generated

**Review**:
- Check `/root/cve-2026-31431-assessment-<hostname>.txt` on each host
- Review summary output
- Identify vulnerable hosts

**Expected output**:
```
CVE-2026-31431 Summary Report
==========================================
Total hosts scanned: 50
Vulnerable hosts: 12

VULNERABLE HOSTS REQUIRING REMEDIATION:
web1.example.com, web2.example.com, db1.example.com, ...

DEFAULT RECOMMENDED MITIGATION: Flag 3
  - Module Blacklist (1) + SELinux (2) = Defense-in-depth
  - Module Blacklist alone can be bypassed by root (via insmod)
  - SELinux blocks syscall even if blacklist is bypassed
  - Covers user_t/unconfined_t (vast majority of scenarios)
```

#### Step 2: Generate Vulnerability Inventory

```bash
# Create inventory of vulnerable hosts with recommendations
ansible-playbook -i inventory quickstart.yml -e generate_inventory=true -e inventory_output_dir=./vulnerable_hosts
```

**What happens**:
- Vulnerable hosts identified
- Recommended mitigation flags calculated per host
- Inventory files generated

**Review**:
```bash
# Check generated inventory
cat vulnerable_hosts/vulnerable_hosts.yml

# Review per-host recommendations
ls vulnerable_hosts/host_vars/
```

#### Step 3: Test Remediation on Non-Production

```bash
# Apply to test/dev hosts first
ansible-playbook -i vulnerable_hosts/vulnerable_hosts.yml cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  --limit 'dev*:test*'
```

**What happens**:
- Mitigations applied to test/dev hosts only
- Services restarted (for seccomp)
- Verification performed

**Verify**:
```bash
# Re-scan test hosts
ansible-playbook -i vulnerable_hosts/vulnerable_hosts.yml quickstart.yml --limit 'dev*:test*'

# Check for "PROTECTED - Defense-in-depth" status
```

**Test applications**:
- Verify critical services work
- Check application functionality
- Monitor logs for issues

#### Step 4: Production Remediation (Staged)

```bash
# Apply to production in stages
# Stage 1: Web tier
ansible-playbook -i vulnerable_hosts/vulnerable_hosts.yml cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  --limit 'web*'

# Stage 2: Application tier
ansible-playbook -i vulnerable_hosts/vulnerable_hosts.yml cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  --limit 'app*'

# Stage 3: Database tier (most critical)
ansible-playbook -i vulnerable_hosts/vulnerable_hosts.yml cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  --limit 'db*'
```

**What happens**:
- Each tier remediated separately
- Services restarted one tier at a time
- Allows for staged validation

**Monitor between stages**:
- Check service availability
- Review application logs
- Verify user experience

#### Step 5: Verification and Documentation

```bash
# Final assessment of all hosts
ansible-playbook -i inventory quickstart.yml
```

**Document**:
- Record which hosts were remediated
- Note any issues encountered
- Update change management records

**Expected final output**:
```
CVE-2026-31431 Summary Report
==========================================
Total hosts scanned: 50
Vulnerable hosts: 0

All hosts protected with defense-in-depth mitigations
```

### Emergency Response Workflow

For **actively exploited** systems or **immediate threats**:

```bash
# Immediate assessment and remediation
ansible-playbook -i inventory quickstart.yml -e apply_remediation=true -e mitigation_flags=3

# Re-verify all hosts
ansible-playbook -i inventory quickstart.yml
```

**Use this approach when**:
- Active exploitation detected
- Critical systems at immediate risk
- Time is more critical than process

**Caution**: This applies mitigations to ALL vulnerable hosts simultaneously. Monitor closely.

### Continuous Monitoring Workflow

For **ongoing compliance** and **new system detection**:

```bash
# Weekly automated scan
0 2 * * 0 ansible-playbook -i inventory quickstart.yml -e generate_inventory=true

# Alert on new vulnerabilities
# (integrate with monitoring system)
```

**Integrate with**:
- Configuration management database (CMDB)
- Security information and event management (SIEM)
- Ticketing systems for remediation tracking

### Custom Mitigation Workflow

For **specific requirements** beyond Flag 3:

```bash
# Use enhanced protection (Flag 7: Blacklist + SELinux + seccomp)
ansible-playbook -i inventory quickstart.yml \
  -e apply_remediation=true \
  -e mitigation_flags=7

# Or customize per-host via inventory
# Edit generated host_vars/*.yml files to set custom flags
vim vulnerable_hosts/host_vars/web1.example.com.yml
# Change: recommended_mitigation_flags: 7

# Apply customized settings
ansible-playbook -i vulnerable_hosts/vulnerable_hosts.yml cve_2026_31431_playbook.yml \
  -e apply_remediation=true
```

### Verification Workflow

After remediation, verify protection:

```bash
# On remediated host:
sudo lsmod | grep algif_aead
# Should return nothing (module not loaded)

sudo modprobe algif_aead
# Should fail: "modprobe: ERROR: could not insert 'algif_aead'"

cat /etc/modprobe.d/blacklist-algif_aead-cve-2026-31431.conf
# Should show blacklist configuration

# Check SELinux policy
sudo semodule -l | grep cve_2026_31431
# Should show: cve_2026_31431_af_alg_deny

# Check seccomp (for services)
systemctl show httpd | grep RestrictAddressFamilies
# Should show: RestrictAddressFamilies=~AF_ALG
```

---

## Quick Start

For users who want to get started immediately:

### Simplest Usage

```bash
# Clone repository
git clone https://github.com/parmstro/cfDr.git
cd cfDr

# Step 1: Assess all hosts
ansible-playbook -i inventory quickstart.yml

# Step 2: Apply recommended mitigations to vulnerable hosts
ansible-playbook -i inventory quickstart.yml --limit vulnerable_hosts -e apply_remediation=true
```

### Using with Custom Inventory

```bash
# Assess with your inventory
ansible-playbook -i /path/to/your/inventory quickstart.yml

# Remediate vulnerable hosts
ansible-playbook -i /path/to/your/inventory quickstart.yml \
  --limit vulnerable_hosts \
  -e apply_remediation=true
```

### Generating Vulnerability Inventory

```bash
# Scan and create inventory of vulnerable hosts
ansible-playbook -i inventory quickstart.yml -e generate_inventory=true

# Review generated files
ls inventory_output/

# Apply mitigations using generated inventory
ansible-playbook -i inventory_output/vulnerable_hosts.yml cve_2026_31431_playbook.yml \
  -e apply_remediation=true
```

---

## Advanced Configuration

### Customizing Mitigation Flags

Override default mitigations per playbook run:

```bash
# Module blacklist only
ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=1

# SELinux only
ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=2

# Module blacklist + SELinux (default recommended)
ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=3

# Enhanced: Blacklist + SELinux + seccomp
ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=7

# Maximum: All mitigations (RHEL 9+ only)
ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=15
```

### Customizing SELinux Domains

Edit `roles/cve_2026_31431/defaults/main.yml`:

```yaml
# Add additional domains to protect
selinux_denied_domains:
  - user_t
  - unconfined_t
  - httpd_t
  - postgresql_t
  - mysqld_t
  - custom_app_t        # Your custom domain
  - another_service_t
```

### Customizing seccomp Services

Edit `roles/cve_2026_31431/defaults/main.yml`:

```yaml
# Add additional services to protect
seccomp_protected_services:
  - httpd
  - nginx
  - postgresql
  - mariadb
  - redis
  - memcached
  - your-custom-service  # Your service
```

### Custom Inventory Output Directory

```bash
# Specify custom output location
ansible-playbook quickstart.yml \
  -e generate_inventory=true \
  -e inventory_output_dir=/path/to/output
```

### Using Sample Playbook Templates

The `sample_playbook.yml` contains multiple examples:

```yaml
# Example 1: Assessment only
- hosts: all
  roles:
    - cve_2026_31431

# Example 2: Module blacklist only
- hosts: all
  vars:
    apply_remediation: true
    mitigation_flags: 1
  roles:
    - cve_2026_31431

# Example 3: Recommended (Blacklist + SELinux)
- hosts: all
  vars:
    apply_remediation: true
    mitigation_flags: 3
  roles:
    - cve_2026_31431
```

### Requirements

- **Ansible**: 2.9 or higher (2.15+ recommended)
- **Privileged access**: sudo/root on target hosts
- **Python**: 2.7 or 3.5+ on target hosts
- **Supported OS**: Red Hat Enterprise Linux, CentOS, Fedora (Debian/Ubuntu limited support)

---

## Additional Resources

### CVE Information and Analysis

**Official Sources**:
- [NVD - CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
- [MITRE CVE Entry](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-31431)

**Security Research and Analysis**:
- [Sysdig - CVE-2026-31431 Analysis](https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds)
- [The Hacker News - Copy Fail Vulnerability](https://thehackernews.com/2026/04/new-linux-copy-fail-vulnerability.html)
- [CERT-EU Security Advisory](https://cert.europa.eu/publications/security-advisories/2026-005/)
- [Help Net Security - Copy Fail Details](https://www.helpnetsecurity.com/2026/04/30/copyfail-linux-lpe-vulnerability-cve-2026-31431/)

### Related Mitigation Projects

Community contributions to CVE-2026-31431 mitigation:

- **[block-copyfail](https://github.com/atgreen/block-copyfail)** - eBPF LSM implementation by Anthony Green
  - Comprehensive eBPF-based mitigation
  - System-wide protection for modern kernels
  - Source for cfDr's eBPF implementation

- **[Blastwall](https://gprocunier.github.io/blastwall/demo.html)** - SELinux policy framework by Greg Procunier
  - Advanced SELinux policy management
  - Multi-CVE protection framework
  - Source for cfDr's SELinux implementation

### Red Hat Specific Resources

**Knowledge Base Articles**:
- [Red Hat Customer Portal - CVE-2026-31431](https://access.redhat.com/security/cve/cve-2026-31431)
- [Red Hat Security Data - Affected Products](https://access.redhat.com/security/data/metrics/)

**Mitigation Guides**:
- [SELinux for Enterprise Linux - User Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/)
- [systemd Security Features](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/managing_systems_using_the_rhel_9_web_console/securing-systemd-services_system-management-using-the-rhel-9-web-console)

### Documentation

**cfDr Extended Documentation**:
- [Enterprise Linux Mitigations Guide](enterprise-linux-mitigations.md) - Comprehensive comparison of all mitigation methods
- [SELinux Mitigation Guide](selinux-mitigation.md) - Detailed SELinux policy implementation
- [seccomp Mitigation Guide](seccomp-mitigation.md) - systemd seccomp filter implementation  
- [eBPF LSM Mitigation Guide](ebpf-lsm-mitigation.md) - eBPF LSM program implementation
- [docs/CONTRIBUTORS.md](CONTRIBUTORS.md) - Contribution guidelines and credits

**Ansible Documentation**:
- [Ansible User Guide](https://docs.ansible.com/ansible/latest/user_guide/)
- [Ansible Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)

---

## Monitoring for Patches

### Red Hat Enterprise Linux

**Primary Source**: Red Hat Customer Portal
- **Security Advisories**: https://access.redhat.com/security/security-updates/
- **Errata Advisories**: https://access.redhat.com/errata/
- **CVE Tracker**: https://access.redhat.com/security/cve/cve-2026-31431

**Notification Methods**:

1. **Email Alerts** (Recommended):
   - Log in to Red Hat Customer Portal
   - Navigate to: Account Settings → Notifications
   - Enable: "Security Advisories" and "Product Errata"
   - Select: RHEL versions you manage

2. **RSS Feeds**:
   - RHEL 7 Security: https://access.redhat.com/blogs/766093/feed
   - RHEL 8 Security: https://access.redhat.com/blogs/1683903/feed
   - RHEL 9 Security: https://access.redhat.com/blogs/5480361/feed
   - All Security: https://access.redhat.com/security/data/oval/com.redhat.rhsa-all.xml

3. **API Access**:
   ```bash
   # Check for kernel security updates
   curl -H "Accept: application/json" \
     "https://access.redhat.com/labs/securitydataapi/cve/CVE-2026-31431.json"
   ```

4. **Automated Monitoring**:
   ```bash
   # Install Red Hat Security Advisories plugin for yum
   sudo yum install yum-plugin-security
   
   # Check for security updates
   sudo yum updateinfo list security
   
   # Check specifically for kernel updates
   sudo yum updateinfo list security kernel
   ```

**What to look for**:
- **RHSA** (Red Hat Security Advisory) for kernel
- Advisory title containing "CVE-2026-31431"
- Affected RHEL versions matching your environment

**Example Advisory Format**:
```
RHSA-2026:XXXX - Important: kernel security update
Severity: Important
CVEs: CVE-2026-31431
Affected Products: RHEL 7, 8, 9
```

### CentOS / Rocky Linux / AlmaLinux

**CentOS Stream**:
- **Announcements**: https://lists.centos.org/pipermail/centos-announce/
- **Security Mailing List**: https://lists.centos.org/mailman/listinfo/centos-security-announce

**Rocky Linux**:
- **Security Tracker**: https://errata.rockylinux.org/
- **Announcements**: https://rockylinux.org/news/

**AlmaLinux**:
- **Errata**: https://errata.almalinux.org/
- **Security**: https://wiki.almalinux.org/security/

### Fedora

**Primary Source**: Fedora Project
- **Updates System**: https://bodhi.fedoraproject.org/
- **Security List**: https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/

**Notification Methods**:
```bash
# Subscribe to security announcements
# Visit: https://lists.fedoraproject.org/admin/lists/security-announce.lists.fedoraproject.org/

# Check for updates
sudo dnf check-update kernel

# View available security updates
sudo dnf updateinfo list security
```

### Ubuntu

**Primary Source**: Ubuntu Security Notices
- **USN Database**: https://ubuntu.com/security/notices
- **CVE Tracker**: https://ubuntu.com/security/CVE-2026-31431

**Notification Methods**:
```bash
# Subscribe to security announcements
# Visit: https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce

# Check for security updates
sudo apt update
sudo apt list --upgradable | grep security

# Ubuntu Security Notices tool
sudo apt install ubuntu-security-tools
usn list --cve CVE-2026-31431
```

### Debian

**Primary Source**: Debian Security Tracker
- **Security Tracker**: https://security-tracker.debian.org/tracker/CVE-2026-31431
- **Security Announcements**: https://www.debian.org/security/

**Notification Methods**:
```bash
# Subscribe to Debian Security Announcements
# Visit: https://lists.debian.org/debian-security-announce/

# Check for security updates
sudo apt update
sudo apt list --upgradable
```

### SUSE / openSUSE

**Primary Source**: SUSE Security
- **Security Updates**: https://www.suse.com/support/update/
- **CVE Database**: https://www.suse.com/security/cve/CVE-2026-31431.html

**Notification Methods**:
```bash
# Check for security patches
sudo zypper list-patches --category security

# Specific CVE check
sudo zypper info --cve CVE-2026-31431
```

### Upstream Kernel

**Linux Kernel Mailing List**:
- **LKML Archives**: https://lkml.org/
- **Security List**: https://www.kernel.org/category/releases.html

**Git Repository**:
```bash
# Monitor kernel git for patches
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

# Search for CVE-2026-31431 patches
git log --all --grep="CVE-2026-31431"
```

### Automated Patch Monitoring Script

Create a monitoring script for your environment:

```bash
#!/bin/bash
# check-cve-2026-31431-patch.sh
# Monitors for CVE-2026-31431 kernel patches

DISTRO=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')

case $DISTRO in
  rhel|centos|rocky|alma)
    yum updateinfo list security kernel 2>/dev/null | grep -i CVE-2026-31431
    ;;
  fedora)
    dnf updateinfo list security kernel 2>/dev/null | grep -i CVE-2026-31431
    ;;
  ubuntu|debian)
    apt-get update -qq
    apt-cache show linux-image-$(uname -r) | grep CVE-2026-31431
    ;;
  sles|opensuse*)
    zypper info --cve CVE-2026-31431 kernel-default
    ;;
esac

# Check Red Hat Security Data API
curl -s "https://access.redhat.com/labs/securitydataapi/cve/CVE-2026-31431.json" | \
  jq -r '.affected_release[] | select(.package | startswith("kernel")) | 
         "\(.product_name): \(.advisory) - \(.package)"'
```

**Schedule with cron**:
```bash
# Check daily for patches
0 6 * * * /usr/local/bin/check-cve-2026-31431-patch.sh | mail -s "CVE-2026-31431 Patch Check" admin@example.com
```

### What to Do When Patches Are Released

1. **Verify patch availability**:
   ```bash
   # Check your distribution's update mechanism
   sudo yum check-update kernel  # RHEL/CentOS/Fedora
   sudo apt update && apt list --upgradable linux-image-*  # Ubuntu/Debian
   ```

2. **Review release notes**:
   - Read vendor advisory for installation instructions
   - Check for any known issues or prerequisites
   - Verify kernel version numbers

3. **Test in non-production**:
   ```bash
   # Apply kernel update to test systems first
   sudo yum update kernel  # RHEL/CentOS/Fedora
   sudo apt upgrade linux-image-*  # Ubuntu/Debian
   sudo reboot
   ```

4. **Verify patch effectiveness**:
   ```bash
   # After reboot, verify kernel version
   uname -r
   
   # Run cfDr assessment to confirm patch
   ansible-playbook -i inventory quickstart.yml
   ```

5. **Plan production rollout**:
   - Schedule maintenance windows
   - Stage kernel updates
   - Plan for service restarts/reboots

6. **Remove temporary mitigations** (optional):
   ```bash
   # After patching, temporary mitigations can be removed
   # However, defense-in-depth recommends keeping them
   
   # If you choose to remove:
   sudo rm /etc/modprobe.d/blacklist-algif_aead-cve-2026-31431.conf
   sudo semodule -r cve_2026_31431_af_alg_deny  # SELinux policy
   # Remove seccomp drop-in files
   # Update initramfs/initrd
   ```

**Recommendation**: Even after kernel patching, consider **keeping defense-in-depth mitigations** in place as protection against future vulnerabilities.

---

## Support and Contributions

### Reporting Issues

Found a bug or have a feature request?

1. **Check existing issues**: https://github.com/parmstro/cfDr/issues
2. **Create new issue**: Include:
   - cfDr version
   - Ansible version
   - Target OS and version
   - Complete error messages
   - Steps to reproduce

### Contributing

We welcome contributions! See [docs/CONTRIBUTORS.md](CONTRIBUTORS.md) for:
- How to contribute code
- Documentation improvements
- Testing and bug reports
- Feature suggestions

### Getting Help

- **Issues**: https://github.com/parmstro/cfDr/issues
- **Discussions**: https://github.com/parmstro/cfDr/discussions

---

## Contributors

cfDr is built on the collective expertise of security professionals:

- **Paul Armstrong** (@parmstro) - Project Lead, Module Blacklist & seccomp implementations
- **Anthony Green** (@atgreen) - eBPF LSM mitigation implementation
- **Greg Procunier** (@gprocunier) - SELinux policy mitigation implementation
- **Claude Sonnet 4.5** - Development assistance, documentation, and research

See [docs/CONTRIBUTORS.md](CONTRIBUTORS.md) for complete contribution details.

---

## License

This project is provided under the MIT License for vulnerability assessment and remediation purposes.

See [LICENSE](LICENSE) for details.

---

## Disclaimer

**IMPORTANT**: This tool provides **temporary mitigations** while waiting for vendor-supplied kernel patches. These mitigations significantly reduce risk but may not provide complete protection in all scenarios.

**cfDr is provided "as is" without warranty**. Always:
- Test in non-production first
- Understand the protection coverage and gaps
- Monitor vendor channels for official patches
- Apply vendor patches when available
- Maintain defense-in-depth even after patching

The contributors and maintainers of cfDr are not responsible for any damage or data loss resulting from the use of this tool.

---

**Last Updated**: 2026-05-02T23:30:00Z

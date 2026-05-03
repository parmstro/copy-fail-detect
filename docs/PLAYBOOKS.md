# Playbook Guide

cfDr provides multiple playbooks for different use cases. Choose the one that fits your needs:

## 🚀 Quick Start (Recommended for Most Users)

### [`quickstart.yml`](quickstart.yml)
**Best for:** First-time users, simple deployments, getting started quickly

**What it does:**
- ✅ Minimal 25-line playbook
- ✅ Assessment mode by default (safe)
- ✅ Recommended mitigations (Module Blacklist + SELinux + seccomp)
- ✅ Easy two-step workflow

**Usage:**
```bash
# Step 1: Find vulnerable systems
ansible-playbook quickstart.yml

# Step 2: Fix vulnerable systems
ansible-playbook quickstart.yml --limit vulnerable_hosts -e apply_remediation=true
```

**Customize:**
```bash
# Use different mitigation flags
ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=3

# Apply to specific hosts
ansible-playbook quickstart.yml -e apply_remediation=true --limit "web1,db1"
```

---

## 📚 Learning Examples

### [`sample_playbook.yml`](sample_playbook.yml)
**Best for:** Learning the role, understanding options, trying different configurations

**What it contains:**
- 6 different example configurations
- Extensive inline comments
- All commented out by default (safe to run)

**Examples included:**
1. **Assessment only** - Default behavior
2. **Module blacklist only** - Safest single mitigation
3. **Recommended** - Module Blacklist + SELinux + seccomp (flag 7)
4. **All mitigations** - Including eBPF LSM (flag 15)
5. **Custom services** - Protect specific web services
6. **Two-step workflow** - Assess, then remediate

**Usage:**
```bash
# Safe to run as-is (only runs Example 1: assessment)
ansible-playbook sample_playbook.yml

# Uncomment an example in the file and run
vim sample_playbook.yml  # Uncomment the example you want
ansible-playbook sample_playbook.yml
```

---

## 🏢 Enterprise Production

### [`cve_2026_31431_playbook.yml`](cve_2026_31431_playbook.yml)
**Best for:** Production environments, enterprise deployments, detailed reporting

**What it does:**
- ✅ Full role implementation with all features
- ✅ Comprehensive summary reporting
- ✅ Dynamic group creation (vulnerable_hosts, safe_hosts)
- ✅ Detailed remediation statistics
- ✅ Production-ready with all safety checks

**Usage:**
```bash
# Assessment with detailed reporting
ansible-playbook cve_2026_31431_playbook.yml

# Apply recommended mitigations (flag 7)
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=7

# Target only vulnerable hosts
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=7 \
  --limit vulnerable_hosts

# Apply all mitigations (RHEL 9 / modern kernels)
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=15
```

---

## 🔧 Legacy / Backwards Compatibility

### [`check_af_alg.yml`](check_af_alg.yml)
**Best for:** Existing deployments using the original playbook, backwards compatibility

**What it does:**
- ⚠️ Original monolithic playbook (before role refactoring)
- ⚠️ Module blacklist mitigation only
- ⚠️ No support for SELinux, seccomp, or eBPF mitigations

**Status:** Maintained for backwards compatibility, but new deployments should use role-based playbooks

**Usage:**
```bash
# Assessment
ansible-playbook check_af_alg.yml

# Remediation
ansible-playbook check_af_alg.yml -e apply_remediation=true --limit vulnerable_hosts
```

**Migration:** See [ROLE_USAGE.md](ROLE_USAGE.md) for migration guide from `check_af_alg.yml` to role-based approach.

---

## 🎯 Decision Guide

| Your Need | Use This Playbook | Complexity | Mitigations |
|-----------|-------------------|------------|-------------|
| **Just getting started** | `quickstart.yml` | ⭐ Simple | 3 (recommended) |
| **Learning the options** | `sample_playbook.yml` | ⭐⭐ Medium | All 4 (examples) |
| **Production deployment** | `cve_2026_31431_playbook.yml` | ⭐⭐⭐ Advanced | All 4 (configurable) |
| **Already using cfDr** | `check_af_alg.yml` | ⭐ Simple | 1 (legacy) |

## 📖 Mitigation Strategies

All playbooks (except legacy) support these mitigation flags:

| Flag | Mitigation | When to Use |
|------|------------|-------------|
| **1** | Module Blacklist | Baseline protection for all systems |
| **2** | SELinux Policy | Primary defense for RHEL/CentOS/Fedora |
| **4** | systemd seccomp | Per-service hardening |
| **8** | eBPF LSM | Advanced (kernel 5.7+, RHEL 9+) |

**Common combinations:**
- `mitigation_flags: 1` - Module blacklist only (legacy equivalent)
- `mitigation_flags: 3` - Module blacklist + SELinux (minimum recommended)
- `mitigation_flags: 7` - Module blacklist + SELinux + seccomp (**RECOMMENDED**)
- `mitigation_flags: 15` - All mitigations (modern systems with eBPF LSM)

**How to calculate:** Add the flag numbers you want
- Want flags 1 + 2 + 4? That's 7
- Want all four? 1 + 2 + 4 + 8 = 15

## 🔍 What Gets Installed?

### Assessment Mode (`apply_remediation: false`)
- ✅ Installs diagnostic tools (lsof, lsmod)
- ✅ Scans for vulnerable systems
- ✅ Generates JSON reports
- ❌ Makes no security changes

### Remediation Mode (`apply_remediation: true`)
Depends on `mitigation_flags`:

**Flag 1 (Module Blacklist):**
- Creates `/etc/modprobe.d/blacklist-algif_aead-cve-2026-31431.conf`
- Updates initramfs/initrd
- Unloads module if currently loaded

**Flag 2 (SELinux):**
- Installs SELinux policy development tools
- Compiles and installs custom policy module
- Blocks AF_ALG socket creation at LSM layer

**Flag 4 (seccomp):**
- Creates systemd drop-in files for configured services
- Adds `RestrictAddressFamilies=~AF_ALG`
- Restarts affected services

**Flag 8 (eBPF LSM):**
- Installs BPF development tools
- Compiles and loads eBPF program
- Creates systemd service for persistence

## 📝 Examples by Use Case

### "I just want to scan my systems"
```bash
ansible-playbook quickstart.yml
```

### "Fix all my vulnerable servers now (recommended way)"
```bash
# Step 1: Find them
ansible-playbook quickstart.yml

# Step 2: Fix them
ansible-playbook quickstart.yml --limit vulnerable_hosts -e apply_remediation=true
```

### "I only want module blacklist (like the old playbook)"
```bash
ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=1
```

### "Give me maximum protection (RHEL 9 / Fedora)"
```bash
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=15 \
  --limit vulnerable_hosts
```

### "Protect my web servers with seccomp"
```bash
# Edit sample_playbook.yml, uncomment Example 5, then:
ansible-playbook sample_playbook.yml --limit webservers
```

## 🆘 Need Help?

- **Getting started**: Start with `quickstart.yml`
- **Understanding options**: Review `sample_playbook.yml`
- **Role details**: See [ROLE_USAGE.md](ROLE_USAGE.md)
- **Mitigation strategies**: See [enterprise-linux-mitigations.md](enterprise-linux-mitigations.md)
- **Issues**: https://github.com/parmstro/cfDr/issues

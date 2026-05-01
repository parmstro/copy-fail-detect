# CVE-2026-31431 Mitigation Options for Enterprise Linux

This document compares mitigation strategies specifically for RHEL, CentOS Stream, Fedora, and their derivatives (AlmaLinux, Rocky Linux, Oracle Linux).

## Available Mitigation Methods

| Method | RHEL 8 | RHEL 9 | Fedora 38+ | Complexity | Effectiveness | Recommended |
|--------|--------|--------|------------|------------|---------------|-------------|
| **Module Blacklist** | ✅ | ✅ | ✅ | Low | Good | ✅ **Yes** |
| **SELinux Policy** | ✅ | ✅ | ✅ | Medium | Excellent | ✅ **Yes** |
| **seccomp (systemd)** | ✅ | ✅ | ✅ | Low | Good | ✅ **Yes** |
| **eBPF LSM** | ❌ | ✅ | ✅ | High | Excellent | ⚠️ Modern only |

## Recommendation for Enterprise Linux

**Best Practice: Defense in Depth - Use Multiple Layers**

```
Layer 1: SELinux Policy (syscall level blocking)
Layer 2: Module Blacklist (prevents module loading)
Layer 3: systemd seccomp (per-service hardening)
```

### Why This Layered Approach?

1. **SELinux** blocks the exploit at the syscall level - even if module is loaded
2. **Module blacklist** prevents casual loading via modprobe
3. **seccomp** provides per-service hardening for critical services

If one layer is bypassed or disabled, others still protect.

## Detailed Comparison

### 1. Module Blacklist (Already Implemented)

**What it does:**
- Blocks `modprobe algif_aead`
- Prevents auto-loading
- Persists via initramfs

**Pros:**
- ✅ Simple to implement (already in playbook)
- ✅ Works on all kernel versions
- ✅ No policy knowledge needed

**Cons:**
- ❌ Can be bypassed with `insmod` (root only)
- ❌ Doesn't protect if module already loaded
- ❌ Reactive (blocks loading, not usage)

**When to use:**
- Always - baseline protection
- Systems without SELinux
- Legacy systems

### 2. SELinux Policy (RECOMMENDED PRIMARY)

**What it does:**
- Denies AF_ALG socket creation for unprivileged domains
- Blocks at kernel LSM layer
- System-wide enforcement

**Pros:**
- ✅ Default on RHEL/CentOS/Fedora
- ✅ Blocks exploit even if module loaded
- ✅ Cannot be bypassed from userspace
- ✅ Audit trail of attempts
- ✅ Fine-grained per-domain control

**Cons:**
- ⚠️ Requires SELinux in Enforcing mode
- ⚠️ Policy development knowledge helpful
- ⚠️ May break legitimate apps (rare)

**Implementation complexity:** Medium

**Coverage:**
```bash
# Check SELinux status
getenforce
# Should show: Enforcing

# SELinux blocks:
socket(AF_ALG, ...)  ← BLOCKED by SELinux
  ↓
  X  Denied before reaching kernel code
```

**When to use:**
- **Primary mitigation for all RHEL/CentOS/Fedora systems**
- Systems in Enforcing mode
- Production environments

### 3. systemd seccomp (RECOMMENDED FOR SERVICES)

**What it does:**
- Per-service syscall filtering
- Blocks AF_ALG socket family
- Integrated with systemd units

**Pros:**
- ✅ Simple systemd directive
- ✅ Per-service granularity
- ✅ No system-wide changes
- ✅ Works without SELinux
- ✅ Easy to deploy

**Cons:**
- ⚠️ Per-service configuration needed
- ⚠️ Only protects systemd services
- ⚠️ Doesn't protect user sessions

**Implementation complexity:** Low

**Coverage:**
```ini
# In service file:
[Service]
RestrictAddressFamilies=~AF_ALG
```

**When to use:**
- Hardening critical services (httpd, nginx, postgresql, etc.)
- Systems with many systemd services
- Complement to SELinux

### 4. eBPF LSM (MODERN SYSTEMS ONLY)

**What it does:**
- Custom BPF program at LSM hooks
- Dynamic, programmable policies
- System-wide enforcement

**Pros:**
- ✅ Very flexible and powerful
- ✅ Can add context-aware rules
- ✅ System-wide enforcement
- ✅ Real-time updates without reboot

**Cons:**
- ❌ RHEL 8: Not available (kernel 4.18)
- ⚠️ RHEL 9: Available but requires setup (kernel 5.14)
- ⚠️ Requires `lsm=...,bpf` boot parameter
- ⚠️ Higher complexity

**Kernel requirements:**
- RHEL 8: ❌ Kernel 4.18 (too old)
- RHEL 9: ✅ Kernel 5.14+ (available)
- Fedora 38+: ✅ Kernel 6.x (available)

**When to use:**
- RHEL 9 / Fedora with modern kernel
- Need custom context-aware policies
- Already using eBPF for other purposes

## Practical Deployment Guide

### Scenario 1: RHEL 8 / CentOS 8

**Available:** Module blacklist, SELinux, seccomp  
**Not available:** eBPF LSM (kernel too old)

**Recommended approach:**
```bash
1. Deploy module blacklist (via playbook)
2. Deploy SELinux policy (primary defense)
3. Harden systemd services with seccomp
```

### Scenario 2: RHEL 9 / CentOS Stream 9

**Available:** All methods  

**Recommended approach:**
```bash
1. Deploy module blacklist (baseline)
2. Deploy SELinux policy (primary defense)
3. Harden systemd services with seccomp
4. Optional: eBPF LSM for advanced use cases
```

### Scenario 3: Fedora 38+

**Available:** All methods

**Recommended approach:**
```bash
1. Deploy module blacklist (baseline)
2. Deploy SELinux policy (primary defense)
3. Harden systemd services with seccomp
4. Optional: eBPF LSM for testing/advanced scenarios
```

## Implementation Priority

For Enterprise Linux environments, implement in this order:

### Priority 1: Module Blacklist (Already Done)
```bash
ansible-playbook check_af_alg.yml -e apply_remediation=true
```
- Quick wins
- Universal compatibility
- Low risk

### Priority 2: SELinux Policy
```bash
# Create and deploy custom SELinux policy
# (See selinux-mitigation.md for details)
```
- Maximum protection
- Native to RHEL/CentOS/Fedora
- Production-ready

### Priority 3: systemd seccomp Hardening
```bash
# Add to critical service units
RestrictAddressFamilies=~AF_ALG
```
- Service-specific hardening
- Defense in depth
- Low overhead

### Priority 4: eBPF LSM (Optional, RHEL 9+)
```bash
# Only if you need dynamic, context-aware policies
# (See ebpf-lsm-mitigation.md for details)
```
- Advanced scenarios only
- Requires expertise
- Not needed for most deployments

## Quick Decision Matrix

**Choose your mitigation based on your environment:**

| Your Environment | Primary Method | Secondary | Tertiary |
|------------------|----------------|-----------|----------|
| RHEL 8 production | SELinux | Module blacklist | seccomp |
| RHEL 9 production | SELinux | Module blacklist | seccomp |
| CentOS Stream 9 | SELinux | Module blacklist | seccomp |
| Fedora Server | SELinux | eBPF LSM | Module blacklist |
| Mixed environment | Module blacklist | SELinux | seccomp |
| SELinux disabled | Module blacklist | seccomp | (Enable SELinux!) |

## Testing All Layers

### Test Script for Enterprise Linux

```bash
#!/bin/bash
# test-all-protections.sh

echo "=== CVE-2026-31431 Protection Test ==="

# Test 1: Module blacklist
echo -n "Module blacklist: "
if modprobe algif_aead 2>&1 | grep -q "Operation not permitted\|Fatal\|blacklist"; then
    echo "✅ PROTECTED"
else
    echo "❌ NOT PROTECTED"
fi

# Test 2: SELinux
echo -n "SELinux: "
if getenforce 2>/dev/null | grep -q "Enforcing"; then
    python3 -c "import socket; socket.socket(38, 2, 0)" 2>&1 | grep -q "Permission denied"
    if [ $? -eq 0 ]; then
        echo "✅ PROTECTED"
    else
        echo "⚠️  ENABLED but not blocking AF_ALG"
    fi
else
    echo "❌ NOT ENFORCING"
fi

# Test 3: Check if any services have seccomp
echo -n "systemd seccomp: "
PROTECTED=$(systemctl show '*' 2>/dev/null | grep -c "RestrictAddressFamilies=.*AF_ALG")
if [ $PROTECTED -gt 0 ]; then
    echo "✅ $PROTECTED services protected"
else
    echo "⚠️  No services hardened"
fi

# Test 4: eBPF LSM (if available)
echo -n "eBPF LSM: "
if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    if bpftool prog list 2>/dev/null | grep -q "lsm"; then
        echo "✅ ACTIVE"
    else
        echo "⚠️  Available but no programs loaded"
    fi
else
    echo "ℹ️  Not available on this kernel"
fi

echo "==================================="
```

## Ansible Playbook Enhancement

Would you like me to enhance the current playbook to:

1. ✅ **Detect which protections are available** (kernel version, SELinux status, etc.)
2. ✅ **Deploy SELinux policy** for RHEL/CentOS/Fedora systems
3. ✅ **Add seccomp to systemd services** automatically
4. ✅ **Test all protection layers** and report status
5. ✅ **Provide remediation priorities** based on system type

This would give you a comprehensive Enterprise Linux mitigation solution!

## Summary: Why Multiple Layers?

**Real-world scenarios where layered defense matters:**

| Scenario | Module Blacklist | SELinux | seccomp | Result |
|----------|------------------|---------|---------|--------|
| Normal attack | ✅ Blocks | ✅ Blocks | ✅ Blocks | Protected |
| SELinux disabled | ✅ Blocks | ❌ Bypassed | ✅ Blocks | Protected |
| Root with insmod | ❌ Bypassed | ✅ Blocks | ✅ Blocks | Protected |
| Unconfined domain | ✅ Blocks | ⚠️ May allow | ✅ Blocks | Protected |
| Non-systemd process | ✅ Blocks | ✅ Blocks | ❌ N/A | Protected |

**No single layer is perfect - defense in depth is key!**

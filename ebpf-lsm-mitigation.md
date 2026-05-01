# eBPF LSM Mitigation for CVE-2026-31431

> **Initial implementation by Anthony Green (@atgreen)**  
> **Based on**: [Block-copyfail](https://github.com/atgreen/block-copyfail)

## Overview

eBPF LSM (Linux Security Modules) allows you to write custom security policies as eBPF programs that hook into kernel security decision points. This provides system-wide protection by intercepting socket creation at the LSM layer.

## Requirements

- Linux kernel 5.7+
- `CONFIG_BPF_LSM=y` in kernel config
- `lsm=...,bpf` in kernel boot parameters
- `libbpf` and `bpftool` installed

## Check if eBPF LSM is Available

```bash
# Check kernel version
uname -r  # Need 5.7+

# Check if BPF LSM is enabled
cat /sys/kernel/security/lsm
# Should include "bpf" in the list: lockdown,yama,selinux,bpf

# Check kernel config
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
# Should show: CONFIG_BPF_LSM=y

# If not enabled, add to kernel parameters
# Edit /etc/default/grub:
# GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,selinux,apparmor,bpf"
# Then: update-grub && reboot
```

## Implementation

### Method 1: BPF LSM Program to Block AF_ALG

```c
// block_af_alg_lsm.bpf.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define AF_ALG 38

char LICENSE[] SEC("license") = "GPL";

// Hook the socket_create LSM hook
SEC("lsm/socket_create")
int BPF_PROG(block_af_alg, int family, int type, int protocol, int kern)
{
    // Allow kernel sockets
    if (kern)
        return 0;
    
    // Block AF_ALG for user processes
    if (family == AF_ALG) {
        bpf_printk("Blocked AF_ALG socket creation attempt");
        return -EPERM;
    }
    
    return 0;
}

// Optional: Log attempts for monitoring
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
};

SEC("lsm/socket_create")
int BPF_PROG(block_af_alg_log, int family, int type, int protocol, int kern)
{
    if (kern)
        return 0;
    
    if (family == AF_ALG) {
        struct event *e;
        
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->uid = bpf_get_current_uid_gid() & 0xffffffff;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
        
        return -EPERM;
    }
    
    return 0;
}
```

### Compile and Load

```bash
# Install dependencies (Ubuntu/Debian)
apt install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool

# Compile the BPF program
clang -O2 -g -target bpf -c block_af_alg_lsm.bpf.c -o block_af_alg_lsm.bpf.o

# Load the BPF LSM program
bpftool prog load block_af_alg_lsm.bpf.o /sys/fs/bpf/block_af_alg \
    type lsm

# Attach to LSM hook
bpftool prog attach pinned /sys/fs/bpf/block_af_alg lsm

# Verify it's loaded
bpftool prog show
bpftool link show

# Monitor blocked attempts
cat /sys/kernel/debug/tracing/trace_pipe | grep "Blocked AF_ALG"
```

### Method 2: Using bpftrace for Quick Testing

```bash
# Install bpftrace
apt install bpftrace  # Debian/Ubuntu
dnf install bpftrace  # Fedora/RHEL

# Simple bpftrace script to monitor AF_ALG attempts
cat > block_af_alg.bt <<'EOF'
#!/usr/bin/env bpftrace

lsm:socket_create
/ arg0 == 38 /  /* AF_ALG = 38 */
{
    printf("Blocked AF_ALG socket: PID=%d CMD=%s UID=%d\n",
           pid, comm, uid);
    override(-1);  /* Return EPERM */
}
EOF

# Run (requires root)
bpftrace block_af_alg.bt
```

### Method 3: Persistent Service with Systemd

```bash
# Create loader script
cat > /usr/local/sbin/load-af-alg-blocker.sh <<'EOF'
#!/bin/bash
set -e

BPF_PROG="/usr/local/lib/bpf/block_af_alg_lsm.bpf.o"
BPF_PIN="/sys/fs/bpf/block_af_alg"

# Load and attach BPF program
if [ ! -f "$BPF_PIN" ]; then
    bpftool prog load "$BPF_PROG" "$BPF_PIN" type lsm
    echo "BPF LSM program loaded and pinned"
fi

# Program auto-attaches on load for LSM
echo "AF_ALG blocking is active"
EOF

chmod +x /usr/local/sbin/load-af-alg-blocker.sh

# Create systemd service
cat > /etc/systemd/system/bpf-block-af-alg.service <<'EOF'
[Unit]
Description=BPF LSM - Block AF_ALG sockets for CVE-2026-31431
After=network.target
Before=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/load-af-alg-blocker.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable bpf-block-af-alg
systemctl start bpf-block-af-alg
```

## Advanced: Context-Aware Filtering

Allow AF_ALG for specific processes (e.g., OpenSSL in containers):

```c
// block_af_alg_selective.bpf.c
#include <linux/bpf.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define AF_ALG 38

char LICENSE[] SEC("license") = "GPL";

// Map of allowed PIDs (can be updated from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);    // PID
    __type(value, __u8);   // 1 = allowed
    __uint(max_entries, 1024);
} allowed_pids SEC(".maps");

SEC("lsm/socket_create")
int BPF_PROG(block_af_alg_selective, int family, int type, int protocol, int kern)
{
    if (kern)
        return 0;
    
    if (family == AF_ALG) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        __u8 *allowed = bpf_map_lookup_elem(&allowed_pids, &pid);
        
        if (allowed && *allowed == 1) {
            // This PID is whitelisted
            return 0;
        }
        
        // Block all other AF_ALG attempts
        bpf_printk("Blocked AF_ALG from PID %d", pid);
        return -EPERM;
    }
    
    return 0;
}
```

Userspace controller to allow specific PIDs:

```bash
# Allow a specific process to use AF_ALG
echo "1" | bpftool map update pinned /sys/fs/bpf/allowed_pids \
    key $PID value stdin

# Revoke permission
bpftool map delete pinned /sys/fs/bpf/allowed_pids key $PID
```

## Testing and Verification

### Test Blocking

```python
#!/usr/bin/env python3
import socket
import sys

try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    print("❌ FAILED: AF_ALG socket created - not protected")
    s.close()
    sys.exit(1)
except PermissionError as e:
    print(f"✅ SUCCESS: AF_ALG blocked by eBPF LSM - {e}")
    sys.exit(0)
except Exception as e:
    print(f"⚠️ ERROR: {e}")
    sys.exit(2)
```

### Monitor Blocked Attempts

```bash
# View kernel trace log
cat /sys/kernel/debug/tracing/trace_pipe

# Or use bpftrace to monitor
bpftrace -e 'lsm:socket_create /arg0 == 38/ { 
    printf("AF_ALG attempt: pid=%d comm=%s\n", pid, comm); 
}'
```

### Check BPF Program Stats

```bash
# Show loaded programs
bpftool prog list

# Show program details
bpftool prog show id <ID>

# Dump program with JIT assembly
bpftool prog dump xlated id <ID>
```

## Advantages

✅ **System-wide enforcement** - All processes protected  
✅ **Kernel-level security** - Cannot be bypassed from userspace  
✅ **Dynamic updates** - Can update policy without reboot  
✅ **Fine-grained control** - Context-aware decisions (PID, UID, comm, etc.)  
✅ **Performance** - Minimal overhead (BPF JIT compiled)  
✅ **Observability** - Built-in logging and tracing  
✅ **No SELinux required** - Works independently  

## Disadvantages

⚠️ **Kernel 5.7+ required** - Not available on older systems  
⚠️ **CONFIG_BPF_LSM needed** - May not be enabled in distro kernels  
⚠️ **Boot parameter change** - Requires `lsm=...bpf` and reboot  
⚠️ **Complexity** - Requires BPF programming knowledge  
⚠️ **Tooling** - Needs libbpf, clang, bpftool installed  

## Distribution Support

| Distribution | Kernel | BPF LSM Available | Notes |
|--------------|--------|-------------------|-------|
| Ubuntu 22.04+ | 5.15+ | ✅ Yes (enable) | Add `lsm=...bpf` to boot params |
| Fedora 34+ | 5.11+ | ✅ Yes | May need boot param |
| RHEL 9+ | 5.14+ | ✅ Yes | May need boot param |
| Debian 11+ | 5.10+ | ⚠️ Partial | Kernel too old, upgrade to 12+ |
| Ubuntu 20.04 | 5.4 | ❌ No | Kernel too old |

## Checking Your System

```bash
#!/bin/bash
# check_bpf_lsm_support.sh

echo "=== BPF LSM Support Check ==="

# Check kernel version
KERNEL_VER=$(uname -r | cut -d. -f1,2)
echo "Kernel version: $(uname -r)"

if (( $(echo "$KERNEL_VER >= 5.7" | bc -l) )); then
    echo "✅ Kernel version sufficient (5.7+)"
else
    echo "❌ Kernel too old (need 5.7+)"
    exit 1
fi

# Check CONFIG_BPF_LSM
if grep -q "CONFIG_BPF_LSM=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "✅ CONFIG_BPF_LSM enabled in kernel"
else
    echo "❌ CONFIG_BPF_LSM not enabled"
    exit 1
fi

# Check if BPF LSM is active
if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo "✅ BPF LSM is active"
else
    echo "⚠️  BPF LSM not in active LSMs"
    echo "Current LSMs: $(cat /sys/kernel/security/lsm)"
    echo "Add 'lsm=...,bpf' to kernel boot parameters"
fi

# Check for tools
for tool in bpftool clang; do
    if command -v $tool &> /dev/null; then
        echo "✅ $tool installed"
    else
        echo "⚠️  $tool not found (install it)"
    fi
done

echo "=== End Check ==="
```

## Comparison with Other Methods

| Feature | eBPF LSM | SELinux | seccomp |
|---------|----------|---------|---------|
| Scope | System-wide | System-wide | Per-process |
| Kernel version | 5.7+ | 2.6+ | 3.5+ |
| Performance | Excellent | Good | Excellent |
| Flexibility | High | Medium | Medium |
| Complexity | High | Medium | Low |
| Distribution | Limited | Wide | Universal |

## Recommendation

**Use eBPF LSM if:**
- Running modern kernel (5.7+)
- Need fine-grained, dynamic control
- Want observability and logging
- Already using BPF for other purposes

**Use SELinux if:**
- RHEL/CentOS/Fedora environment
- Want proven, stable solution
- Need policy management tools

**Use seccomp if:**
- Protecting specific services
- Need portable solution
- Want simple systemd integration

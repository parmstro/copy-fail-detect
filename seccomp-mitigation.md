# seccomp-bpf Mitigation for CVE-2026-31431

## Overview

Seccomp (Secure Computing Mode) with BPF filters can block the `socket()` syscall when it attempts to create AF_ALG sockets. This is a per-process mitigation that can be applied to services and applications.

## How It Works

```
User process calls socket(AF_ALG, SOCK_SEQPACKET, 0)
    ↓
Kernel seccomp filter intercepts syscall
    ↓
BPF program checks: family == AF_ALG?
    ↓
If YES → Return EPERM (Permission Denied)
If NO  → Allow syscall to proceed
```

## Implementation Methods

### Method 1: Systemd Service Hardening

For services managed by systemd (most modern Linux systems):

```ini
# /etc/systemd/system/myservice.service.d/seccomp-af-alg.conf
[Service]
SystemCallFilter=~socket
SystemCallFilter=socket:EPERM

# Or more specifically block just AF_ALG:
SystemCallFilter=~@network-io
SystemCallFilter=@network-io
SystemCallFilter=socket:EPERM

# Alternatively, use SocketBindDeny (systemd 252+)
RestrictAddressFamilies=~AF_ALG
```

**Example: Protecting nginx**

```bash
# Create override directory
mkdir -p /etc/systemd/system/nginx.service.d/

# Create seccomp override
cat > /etc/systemd/system/nginx.service.d/block-af-alg.conf <<'EOF'
[Service]
# Block AF_ALG socket family
RestrictAddressFamilies=~AF_ALG

# Additional hardening
SystemCallFilter=~@privileged @resources
SystemCallFilter=~@mount
EOF

# Reload and restart
systemctl daemon-reload
systemctl restart nginx

# Verify
systemctl show nginx | grep RestrictAddressFamilies
```

### Method 2: Custom seccomp-bpf Program

For manual process control:

```c
// block_af_alg.c - Compile: gcc -o block_af_alg block_af_alg.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <errno.h>

#define AF_ALG 38

// BPF filter to block AF_ALG sockets
static struct sock_filter filter[] = {
    // Load syscall number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    
    // Check if syscall is socket()
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 4),
    
    // Load first argument (domain/family)
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    
    // Check if family == AF_ALG (38)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_ALG, 0, 1),
    
    // If AF_ALG, return EPERM
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    
    // Otherwise allow
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static struct sock_fprog prog = {
    .len = sizeof(filter) / sizeof(filter[0]),
    .filter = filter,
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        fprintf(stderr, "Example: %s /bin/bash\n", argv[0]);
        return 1;
    }
    
    // Enable seccomp
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        return 1;
    }
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        return 1;
    }
    
    printf("seccomp filter installed - AF_ALG sockets blocked\n");
    
    // Execute the target command
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 1;
}
```

**Compile and use:**

```bash
# Compile
gcc -o block_af_alg block_af_alg.c

# Run a shell with AF_ALG blocked
./block_af_alg /bin/bash

# Test in that shell
python3 -c "import socket; socket.socket(38, 2, 0)"
# Should fail with: PermissionError: [Errno 1] Operation not permitted
```

### Method 3: libseccomp Wrapper

Using libseccomp for easier policy management:

```c
// af_alg_block_libseccomp.c
// Compile: gcc -o af_alg_block af_alg_block_libseccomp.c -lseccomp
#include <stdio.h>
#include <unistd.h>
#include <seccomp.h>
#include <errno.h>

#define AF_ALG 38

int main(int argc, char *argv[]) {
    scmp_filter_ctx ctx;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }
    
    // Create seccomp context - default allow
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        perror("seccomp_init");
        return 1;
    }
    
    // Add rule: deny socket() with AF_ALG
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                         SCMP_A0(SCMP_CMP_EQ, AF_ALG)) < 0) {
        perror("seccomp_rule_add");
        seccomp_release(ctx);
        return 1;
    }
    
    // Load the filter
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        return 1;
    }
    
    seccomp_release(ctx);
    
    printf("AF_ALG socket creation blocked via seccomp\n");
    
    // Execute command
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 1;
}
```

## System-Wide Application

### Using systemd for all services

```bash
# Create global drop-in
mkdir -p /etc/systemd/system/service.d/

cat > /etc/systemd/system/service.d/90-block-af-alg.conf <<'EOF'
[Service]
# Block AF_ALG for all services by default
# Services that need it can override
RestrictAddressFamilies=~AF_ALG
EOF

# Reload systemd
systemctl daemon-reload

# Apply to existing services
systemctl restart '*'
```

### Container/Sandbox Wrapper

```bash
#!/bin/bash
# /usr/local/bin/secure-exec
# Wrapper to run commands with AF_ALG blocked

# Use firejail if available
if command -v firejail &> /dev/null; then
    exec firejail --seccomp='socket:AF_ALG:EPERM' "$@"
fi

# Use systemd-run if available
if command -v systemd-run &> /dev/null; then
    exec systemd-run --user --scope \
        -p RestrictAddressFamilies=~AF_ALG \
        -- "$@"
fi

# Fallback: warn
echo "Warning: No seccomp wrapper available" >&2
exec "$@"
```

## Testing and Verification

### Test Script

```python
#!/usr/bin/env python3
# test_af_alg_block.py
import socket
import sys

AF_ALG = 38

print("Testing AF_ALG socket creation...")

try:
    s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    print("❌ FAIL: AF_ALG socket created (vulnerable)")
    s.close()
    sys.exit(1)
except PermissionError:
    print("✅ PASS: AF_ALG blocked by seccomp (Permission denied)")
    sys.exit(0)
except OSError as e:
    if e.errno == 1:  # EPERM
        print("✅ PASS: AF_ALG blocked (errno 1)")
        sys.exit(0)
    else:
        print(f"⚠️  UNKNOWN: {e}")
        sys.exit(2)
```

### Verify seccomp is active

```bash
# Check process seccomp status
grep Seccomp /proc/$$/status
# 0 = disabled
# 1 = strict mode
# 2 = filter mode (what we want)

# For systemd service
systemctl show <service> | grep -i seccomp
```

## Advantages

✅ **Per-process control** - Can apply to specific services  
✅ **No kernel policy needed** - Works without SELinux/AppArmor  
✅ **Minimal overhead** - BPF filters are very fast  
✅ **Portable** - Works on any kernel 3.5+ with seccomp  
✅ **Systemd integration** - Easy to deploy via unit files  

## Disadvantages

⚠️ **Per-process only** - Must configure each service  
⚠️ **No system-wide default** - Unlike SELinux policies  
⚠️ **Requires process cooperation** - Process must install filter  
⚠️ **Can be bypassed** - If process doesn't install filter  

## Integration with CVE-2026-31431 Playbook

Would you like me to add seccomp-based remediation tasks to the Ansible playbook? This could:

1. Detect systemd services
2. Add AF_ALG restrictions to service units
3. Create system-wide defaults
4. Test protection effectiveness

This provides defense-in-depth alongside the module blacklist!

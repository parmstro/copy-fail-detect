# SELinux Mitigation for CVE-2026-31431

> **Initial implementation by Greg Procunier (@gprocunier)**  
> **SELinux expertise**: [Blastwall](https://gprocunier.github.io/blastwall/demo.html) - SELinux policy framework

## Overview

Instead of blacklisting the kernel module, we can use SELinux to prevent unprivileged processes from creating AF_ALG sockets entirely. This blocks the exploit at the syscall level before it ever reaches the vulnerable kernel code.

## How It Works

The exploit requires:
1. Creating an AF_ALG socket: `socket(AF_ALG, SOCK_SEQPACKET, 0)`
2. Binding to AEAD algorithm
3. Triggering the vulnerability

SELinux can deny step 1 for all unprivileged domains.

## Implementation

### Option 1: Custom SELinux Policy Module

Create a policy that denies AF_ALG socket creation:

```bash
# Create policy file: deny_af_alg.te
cat > deny_af_alg.te <<'EOF'
policy_module(deny_af_alg, 1.0)

require {
    type user_t;
    type unconfined_t;
    class alg_socket { create };
}

# Deny AF_ALG socket creation for user domains
# Allow only for specific trusted domains if needed
neverallow user_t self:alg_socket create;

# For confined users (adjust as needed for your environment)
dontaudit user_t self:alg_socket { create bind };
EOF

# Compile and install the policy
checkmodule -M -m -o deny_af_alg.mod deny_af_alg.te
semodule_package -o deny_af_alg.pp -m deny_af_alg.mod
semodule -i deny_af_alg.pp
```

### Option 2: Modify Existing Policy with Boolean

Add a tunable to existing policy:

```bash
# Check current policy for alg_socket
sesearch -A -c alg_socket

# Create boolean-based policy
cat > af_alg_control.te <<'EOF'
policy_module(af_alg_control, 1.0)

require {
    type user_t;
    class alg_socket { create bind };
}

gen_tunable(allow_af_alg_sockets, false)

tunable_policy(`allow_af_alg_sockets', `
    allow user_t self:alg_socket { create bind };
', `
    dontaudit user_t self:alg_socket *;
')
EOF

# Compile and load
checkmodule -M -m -o af_alg_control.mod af_alg_control.te
semodule_package -o af_alg_control.pp -m af_alg_control.mod
semodule -i af_alg_control.pp

# Disable AF_ALG by default
setsebool -P allow_af_alg_sockets off
```

### Option 3: Targeted Domain Restriction

For specific applications/users:

```bash
# Deny for specific domain (e.g., webapp_t)
cat > webapp_af_alg_deny.te <<'EOF'
policy_module(webapp_af_alg_deny, 1.0)

require {
    type webapp_t;
    class alg_socket { create };
}

# Web applications should never need AF_ALG
dontaudit webapp_t self:alg_socket *;
EOF
```

## Verification

### Test that AF_ALG is blocked:

```bash
# As unprivileged user, try to create AF_ALG socket
python3 <<'EOF'
import socket
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    print("VULNERABLE: AF_ALG socket created")
    s.close()
except PermissionError as e:
    print(f"PROTECTED: {e}")
except OSError as e:
    print(f"PROTECTED: {e}")
EOF
```

### Check SELinux denials:

```bash
# Look for denials
ausearch -m avc -ts recent | grep alg_socket

# Should see something like:
# type=AVC msg=audit(...): avc: denied { create } for pid=... comm="python3" 
# scontext=user_u:user_r:user_t:s0 tcontext=user_u:user_r:user_t:s0 
# tclass=alg_socket permissive=0
```

## Advantages

✅ **Blocks at syscall level** - Exploit can't even reach vulnerable code  
✅ **No module blacklist needed** - Module can stay loaded for privileged processes  
✅ **Fine-grained control** - Can allow specific domains/applications  
✅ **Defense in depth** - Works even if module is manually loaded  
✅ **Audit trail** - SELinux logs all blocked attempts  

## Disadvantages

⚠️ **Requires SELinux enabled** - Not available on all systems  
⚠️ **Policy complexity** - Requires SELinux knowledge  
⚠️ **May break legitimate apps** - Some apps might use AF_ALG crypto  
⚠️ **Confined mode needed** - Unconfined domains may bypass  

## Combining with Module Blacklist

**Best Practice: Use Both**

```
Defense Layer 1: SELinux blocks AF_ALG socket creation (syscall level)
Defense Layer 2: Module blacklist prevents algif_aead loading (module level)
```

If SELinux is bypassed or disabled, blacklist still protects.  
If blacklist is bypassed (insmod), SELinux still protects.

## Distribution-Specific Notes

### RHEL/CentOS/Fedora
- SELinux enabled by default
- Use `semanage` and `semodule` as shown above

### Debian/Ubuntu
- SELinux available but not default (AppArmor is)
- Install: `apt install selinux-basics selinux-policy-default`
- Enable: `selinux-activate`

### Check if SELinux is available:
```bash
# Check status
getenforce

# If "Enforcing" or "Permissive", SELinux is available
# If "Disabled" or command not found, SELinux not active
```

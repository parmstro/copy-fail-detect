## Role-Based Architecture

The CVE-2026-31431 mitigation has been refactored into a professional Ansible role with the following improvements:

### Benefits of Role-Based Approach

1. **Better Organization** - Logical separation of concerns
2. **Reusability** - Can be used across multiple playbooks and projects
3. **Maintainability** - Each mitigation strategy is isolated in its own task file
4. **Flexibility** - Bitwise flags allow fine-grained control
5. **Testability** - Easier to test individual components

### Directory Structure

```
roles/cve_2026_31431/
├── README.md                    # Role documentation
├── defaults/                    # Default variables
│   └── main.yml                 # Bitwise flags and configuration
├── tasks/                       # Task files
│   ├── main.yml                 # Main orchestration
│   ├── preflight.yml            # Pre-flight checks
│   ├── assessment.yml           # Vulnerability assessment
│   ├── remediation_module_blacklist.yml
│   ├── remediation_selinux.yml
│   ├── remediation_seccomp.yml
│   ├── remediation_ebpf.yml
│   ├── reporting.yml            # Report generation
│   └── cleanup.yml              # Removal/cleanup
├── templates/                   # Jinja2 templates
│   ├── blacklist.conf.j2
│   ├── selinux_policy.te.j2
│   ├── seccomp_dropin.conf.j2
│   ├── block_af_alg_lsm.bpf.c.j2
│   └── ebpf_loader.service.j2
├── handlers/                    # Event handlers
│   └── main.yml
├── vars/                        # Internal variables
│   └── main.yml
└── meta/                        # Role metadata
    └── main.yml
```

### Bitwise Flag System

The role uses bitwise flags to control which mitigations are applied:

```yaml
# Flag definitions
MITIGATE_MODULE_BLACKLIST: 1  # 0b0001
MITIGATE_SELINUX:          2  # 0b0010
MITIGATE_SECCOMP:          4  # 0b0100
MITIGATE_EBPF_LSM:         8  # 0b1000

# Example combinations
mitigation_flags: 1   # Module blacklist only
mitigation_flags: 3   # Module blacklist + SELinux (1 + 2)
mitigation_flags: 7   # Module blacklist + SELinux + seccomp (1 + 2 + 4)
mitigation_flags: 15  # All mitigations (1 + 2 + 4 + 8)
```

**How it works:**

The role uses bitwise AND operations to check if a specific mitigation is enabled:

```yaml
when: (mitigation_flags | int) & MITIGATE_SELINUX
```

This allows you to combine multiple mitigations by simply adding the flag values.

### Quick Start

#### 1. Assessment Only

```bash
ansible-playbook cve_2026_31431_playbook.yml
```

#### 2. Apply Module Blacklist + SELinux (Recommended)

```bash
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=3
```

#### 3. Apply All Mitigations Except eBPF (Default)

```bash
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=7
```

#### 4. Target Only Vulnerable Hosts

```bash
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=7 \
  --limit vulnerable_hosts
```

### Using the Role in Your Playbooks

#### Method 1: Include in Playbook

```yaml
---
- name: Secure systems against CVE-2026-31431
  hosts: all
  become: true
  gather_facts: true
  
  vars:
    apply_remediation: true
    mitigation_flags: 7
  
  roles:
    - cve_2026_31431
```

#### Method 2: Role Import

```yaml
---
- name: Security hardening
  hosts: all
  become: true
  
  tasks:
    - name: Mitigate CVE-2026-31431
      import_role:
        name: cve_2026_31431
      vars:
        apply_remediation: true
        mitigation_flags: 7
```

#### Method 3: Conditional Application

```yaml
---
- name: Targeted mitigation
  hosts: all
  become: true
  
  tasks:
    - name: Apply to RHEL 9 systems only
      include_role:
        name: cve_2026_31431
      vars:
        apply_remediation: true
        mitigation_flags: 15  # All mitigations including eBPF
      when: 
        - ansible_os_family == "RedHat"
        - ansible_distribution_major_version == "9"
```

### Advanced Usage

#### Customize Services for seccomp Protection

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
          - php-fpm
```

#### Customize SELinux Denied Domains

```yaml
- hosts: all
  become: true
  roles:
    - role: cve_2026_31431
      vars:
        apply_remediation: true
        mitigation_flags: 2  # SELinux only
        selinux_denied_domains:
          - user_t
          - httpd_t
          - mysqld_t
          - custom_app_t
```

#### Use Tags for Granular Control

```bash
# Run only assessment
ansible-playbook playbook.yml --tags assessment

# Apply only SELinux mitigation
ansible-playbook playbook.yml \
  -e apply_remediation=true \
  --tags selinux

# Skip eBPF LSM
ansible-playbook playbook.yml \
  -e apply_remediation=true \
  --skip-tags ebpf
```

### Comparison: Old vs New Approach

#### Old Playbook Approach

```
check_af_alg.yml (400+ lines)
├── All logic in one file
├── Hard to maintain
├── Difficult to test individual components
├── No reusability
└── apply_remediation: true/false only
```

#### New Role-Based Approach

```
roles/cve_2026_31431/
├── Modular task files (9 separate files)
├── Clear separation of concerns
├── Easy to maintain and test
├── Reusable across projects
├── Bitwise flags for fine-grained control
└── Templates for all configurations
```

### Migration from Old Playbook

If you're using the old `check_af_alg.yml` playbook:

```bash
# Old way
ansible-playbook check_af_alg.yml -e apply_remediation=true

# New way (equivalent)
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=1  # Module blacklist only (old default)
```

For defense-in-depth (recommended):

```bash
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=7  # Module blacklist + SELinux + seccomp
```

### Understanding the Task Flow

1. **Pre-flight Checks** (`preflight.yml`)
   - Install required tools (lsof, lsmod)
   - Check eBPF LSM availability (if enabled)
   - Verify SELinux status (if enabled)
   - Check systemd availability (if seccomp enabled)

2. **Assessment** (`assessment.yml`)
   - Gather kernel information
   - Check module status
   - Detect dependent modules
   - Check existing protections
   - Generate vulnerability report

3. **Remediation** (conditional based on flags)
   - **Module Blacklist** (`remediation_module_blacklist.yml`)
     - Unload module if loaded
     - Create blacklist configuration
     - Update initramfs/initrd
     - Verify protection
   
   - **SELinux** (`remediation_selinux.yml`)
     - Install policy development tools
     - Generate SELinux policy from template
     - Compile and install policy module
     - Test blocking functionality
   
   - **systemd seccomp** (`remediation_seccomp.yml`)
     - Detect running services
     - Create drop-in configurations
     - Reload systemd
     - Restart services
     - Verify restrictions
   
   - **eBPF LSM** (`remediation_ebpf.yml`)
     - Install BPF development tools
     - Generate BPF program from template
     - Compile BPF object
     - Load into kernel
     - Create systemd service for persistence

4. **Reporting** (`reporting.yml`)
   - Generate JSON report
   - Display summary
   - Show available mitigations
   - Provide next-step recommendations

5. **Cleanup** (`cleanup.yml` - optional)
   - Remove blacklist configurations
   - Uninstall SELinux policy
   - Remove seccomp drop-ins
   - Unload eBPF programs

### Testing

Test individual mitigations:

```bash
# Test module blacklist only
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=1 \
  --check  # Dry run

# Test SELinux only (actual run)
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=2

# Test all on specific host
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=15 \
  --limit testhost.example.com
```

### Best Practices

1. **Always assess first**
   ```bash
   ansible-playbook cve_2026_31431_playbook.yml
   ```

2. **Test in dev/staging**
   ```bash
   ansible-playbook cve_2026_31431_playbook.yml \
     -e apply_remediation=true \
     -e mitigation_flags=7 \
     --limit staging
   ```

3. **Apply to production**
   ```bash
   ansible-playbook cve_2026_31431_playbook.yml \
     -e apply_remediation=true \
     -e mitigation_flags=7 \
     --limit production
   ```

4. **Use defense-in-depth**
   - Don't rely on single mitigation
   - Recommended: flags=7 (module blacklist + SELinux + seccomp)

5. **Monitor and verify**
   - Check JSON reports
   - Verify applied mitigations
   - Test blocking functionality
   - Monitor audit logs

### Troubleshooting

#### Role not found

```bash
# Ensure you're in the right directory
ls -la roles/cve_2026_31431/

# Or specify roles path
ansible-playbook -i inventory \
  --roles-path=./roles \
  cve_2026_31431_playbook.yml
```

#### Mitigations not applied

Check the mitigation flags:

```bash
# Add verbose output
ansible-playbook cve_2026_31431_playbook.yml \
  -e apply_remediation=true \
  -e mitigation_flags=7 \
  -vv
```

#### SELinux policy fails

```bash
# Check SELinux status
ansible all -m shell -a "getenforce"

# Check policy compilation logs
ansible all -m shell -a "journalctl -xe | grep semodule"
```

### Support

- **Role Documentation**: `roles/cve_2026_31431/README.md`
- **Mitigation Guides**: See `*-mitigation.md` files in repository root
- **Issues**: https://github.com/parmstro/copy-fail-detect/issues

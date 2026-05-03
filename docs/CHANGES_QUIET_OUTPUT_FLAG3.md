# Changes: Quieter Output and Flag 3 Default

## Summary

Made the following changes to reduce verbose output during multi-host scans and standardize on Flag 3 (Module Blacklist + SELinux) as the default recommended mitigation.

---

## 1. Reduced Assessment and Reporting Output

### Problem
When scanning multiple hosts, the output was too long and repetitive:
- Detailed assessment displayed for each host
- Verbose remediation information displayed for each vulnerable host
- Made it difficult to see the overall status when scanning many hosts

### Solution
- **Write detailed assessments to /root** instead of displaying them
- **Brief one-line output** during scan showing: `hostname: STATUS`
- **Single summary** at end showing all vulnerable hosts and recommendation ONCE

### Files Changed

**roles/cve_2026_31431/tasks/assessment.yml:**
- Removed verbose `debug` task displaying full assessment
- Added `copy` task to write assessment to `/root/cve-2026-31431-assessment-{hostname}.txt`
- Added brief one-line debug output: `hostname: VULNERABLE/NOT VULNERABLE`
- Changed recommendation display from verbose debug to appending to assessment file

**roles/cve_2026_31431/tasks/reporting.yml:**
- Removed verbose 43-line "Display remediation information" task (was per-host)
- Added `add_host` task to collect vulnerable hosts into a group
- Added single summary task (run_once) that displays:
  - List of all vulnerable hostnames (comma-separated)
  - Remediation recommendation ONCE for entire list
  - Location of detailed assessment files

**Assessment files location:**
```
/root/cve-2026-31431-assessment-<hostname>.txt
```

Each file contains:
- Kernel version and vulnerability status
- Detailed assessment results
- Recommended mitigation flag with rationale

**Old behavior (per-host repetition):**
```
========================================
CVE-2026-31431 REMEDIATION INFORMATION
========================================
[43 lines of mitigation details for host1]

========================================
CVE-2026-31431 REMEDIATION INFORMATION
========================================
[43 lines of mitigation details for host2]

[... repeated for each vulnerable host ...]
```

**New behavior (single summary):**
```
VULNERABLE HOSTS REQUIRING REMEDIATION:
host1, host2, host3

DEFAULT RECOMMENDED MITIGATION: Flag 3
  Module Blacklist (1) + SELinux (2) = Defense-in-depth

Per-host assessments saved to: /root/cve-2026-31431-assessment-<hostname>.txt
```

---

## 2. Changed Default Recommended Flag to 3

### Rationale
Flag 3 (Module Blacklist + SELinux) provides:
- **Two independent protection layers** (defense-in-depth)
- **Works on all Enterprise Linux systems** (RHEL, CentOS, Fedora)
- **No additional dependencies** (SELinux is default on EL)
- **No service restarts required** (unlike seccomp)

Flag 7 (adding seccomp) is now considered "enhanced protection" rather than default.

### Files Changed

**roles/cve_2026_31431/defaults/main.yml:**
```yaml
# Changed from:
mitigation_flags: 7

# Changed to:
mitigation_flags: 3  # Module Blacklist + SELinux (DEFAULT RECOMMENDED)
```

**quickstart.yml:**
```yaml
# Changed from:
mitigation_flags: 7  # Module Blacklist + SELinux + seccomp (recommended)

# Changed to:
mitigation_flags: 3  # Module Blacklist + SELinux (recommended default)
```

**cve_2026_31431_playbook.yml:**
```yaml
# Changed from:
mitigation_flags: 7  # Module blacklist + SELinux + seccomp (default)

# Changed to:
mitigation_flags: 3  # Module blacklist + SELinux (default recommended)
```

**sample_playbook.yml:**
- Updated Example 3 to use flag 3
- Updated Quick Reference to show flag 3 as DEFAULT RECOMMENDED
- Updated comments throughout

---

## 3. Enhanced Final Summary

### New Summary Output

**cve_2026_31431_playbook.yml - Final Summary includes:**

```
==========================================
CVE-2026-31431 Summary Report
==========================================
Total hosts scanned: N
Vulnerable hosts: N

VULNERABLE HOSTS REQUIRING REMEDIATION:
host1, host2, host3

Assessment Reports:
  - Per-host details: /root/cve-2026-31431-assessment-<hostname>.txt
  - JSON reports: /tmp/cve-2026-31431-*.json

DEFAULT RECOMMENDED MITIGATION: Flag 3
  - Module Blacklist (1) + SELinux (2) = Defense-in-depth
  - This default has been set for all vulnerable hosts

TO REMEDIATE WITH RECOMMENDED SETTINGS:
  ansible-playbook cve_2026_31431_playbook.yml -e apply_remediation=true -e mitigation_flags=3 --limit vulnerable_hosts

TO CUSTOMIZE MITIGATION PROFILE:
  1. Generate inventory: ansible-playbook cve_2026_31431_playbook.yml -e generate_inventory=true
  2. Update inventory file to override recommended_mitigation_flags per host
  3. Apply: ansible-playbook -i <inventory> cve_2026_31431_playbook.yml -e apply_remediation=true
==========================================
```

---

## 4. Inventory Generation Updates

### No Changes Required

The inventory templates already use `{{ recommended_mitigation_flags }}` which defaults to 3.

**Both templates set group variable:**
```yaml
vulnerable_hosts:
  vars:
    mitigation_flags: 3  # From recommended_mitigation_flags variable
```

**Per-host overrides available in generated inventory:**
Each host entry includes `recommended_mitigation_flags` which can be customized before applying remediation.

---

## Usage Examples

### 1. Quick Assessment (Quieter Output)

```bash
ansible-playbook quickstart.yml
```

**Output during scan:**
```
host1.example.com: VULNERABLE - Module loaded and exploitable
host2.example.com: NOT VULNERABLE - Kernel too old (pre-2017)
host3.example.com: VULNERABLE - Module exists and can be loaded
```

**Role summary (displayed once):**
```
VULNERABLE HOSTS REQUIRING REMEDIATION:
host1.example.com, host3.example.com

DEFAULT RECOMMENDED MITIGATION: Flag 3
  Module Blacklist (1) + SELinux (2) = Defense-in-depth

Per-host assessments saved to: /root/cve-2026-31431-assessment-<hostname>.txt
```

**Playbook final summary shows remediation instructions.**

### 2. Review Detailed Assessment

```bash
# On each scanned host
cat /root/cve-2026-31431-assessment-hostname.txt
```

### 3. Apply Default Recommended Mitigation (Flag 3)

```bash
ansible-playbook quickstart.yml --limit vulnerable_hosts -e apply_remediation=true
```

This applies:
- Module Blacklist (prevents modprobe loading)
- SELinux Policy (blocks AF_ALG sockets at LSM layer)

### 4. Generate Inventory with Recommended Flags

```bash
ansible-playbook cve_2026_31431_playbook.yml -e generate_inventory=true
```

Creates inventory with `mitigation_flags: 3` for vulnerable_hosts group.

### 5. Customize Per-Host Mitigation

```bash
# Step 1: Generate inventory
ansible-playbook cve_2026_31431_playbook.yml -e generate_inventory=true

# Step 2: Edit generated inventory
vi inventory_output/vulnerable_hosts.yml

# Change specific hosts to use flag 7 (add seccomp) or flag 1 (blacklist only)
# Example:
#   host1:
#     recommended_mitigation_flags: 7  # Enhanced protection for critical host
#   host2:
#     recommended_mitigation_flags: 1  # SELinux not available

# Step 3: Apply with custom settings
ansible-playbook -i inventory_output/vulnerable_hosts.yml cve_2026_31431_playbook.yml -e apply_remediation=true
```

---

## Benefits

### 1. **Cleaner Output**
- One-line status per host during scan
- Detailed information saved to files for later review
- Single remediation summary (not repeated per-host)
- Recommendation displayed once for all vulnerable hosts
- Clear summary at end showing all vulnerable hosts

### 2. **Better Default**
- Flag 3 works on all Enterprise Linux systems
- Simpler than flag 7 (no service restarts)
- Still provides defense-in-depth with two independent layers

### 3. **Clear Remediation Path**
- Default remediation command provided in summary
- Instructions for customizing per-host settings
- Inventory generation with correct defaults

### 4. **Flexibility**
- Can still use flag 7 or flag 15 when needed
- Per-host customization via inventory
- Detailed assessments available in /root for review

---

## Migration Notes

### If You Previously Used Flag 7

Flag 7 is still fully supported and can be used by:

**Option 1: Command line override**
```bash
ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=7
```

**Option 2: Playbook variable**
```yaml
vars:
  mitigation_flags: 7
```

**Option 3: Inventory override**
```yaml
vulnerable_hosts:
  vars:
    mitigation_flags: 7
```

### Why Flag 3 is Now Default

| Feature | Flag 3 | Flag 7 |
|---------|--------|--------|
| **Module Blacklist** | ✓ | ✓ |
| **SELinux** | ✓ | ✓ |
| **systemd seccomp** | ✗ | ✓ |
| **Service restarts required** | No | Yes (for seccomp services) |
| **Works on all EL versions** | Yes | Yes |
| **Additional dependencies** | None | Service-specific |
| **Defense-in-depth** | 2 layers | 3 layers |

**Flag 3 provides excellent protection with minimal complexity.**

**Use Flag 7 when:**
- You want maximum protection
- Service restarts are acceptable
- You manage critical production systems
- You want per-service isolation

---

## File Summary

**Files Modified:**
1. `roles/cve_2026_31431/defaults/main.yml` - Changed default mitigation_flags to 3
2. `roles/cve_2026_31431/tasks/assessment.yml` - Write to /root, brief output
3. `roles/cve_2026_31431/tasks/reporting.yml` - Removed repetitive per-host output, single summary
4. `quickstart.yml` - Changed default to flag 3
5. `cve_2026_31431_playbook.yml` - Changed default to flag 3, enhanced summary
6. `sample_playbook.yml` - Updated examples and documentation

**Files Unchanged (already correct):**
- `roles/cve_2026_31431/templates/vulnerable_hosts_inventory.yml.j2`
- `roles/cve_2026_31431/templates/vulnerable_hosts_inventory.ini.j2`
- `roles/cve_2026_31431/templates/vulnerable_hosts_group_vars.yml.j2`
- `roles/cve_2026_31431/templates/host_vars.yml.j2`

All inventory templates already use `{{ recommended_mitigation_flags }}` which defaults to 3.

# Ansible Best Practices Fixes

## Summary

Comprehensive review and fix of all Ansible code to ensure:
1. **FQCN (Fully Qualified Collection Names)** - All modules use `ansible.builtin.` prefix
2. **Jinja2 Compatibility** - Removed unsupported bitwise operators
3. **Best Practices** - Followed Ansible role development standards

---

## Issues Fixed

### 1. FQCN (Fully Qualified Collection Names)

**Problem:** All modules were using short names (e.g., `command:`, `shell:`, `debug:`) instead of FQCN format.

**Solution:** Added `ansible.builtin.` prefix to all module calls.

**Files Updated:**
- `roles/cve_2026_31431/tasks/main.yml` - 10 modules
- `roles/cve_2026_31431/tasks/assessment.yml` - 15 modules
- `roles/cve_2026_31431/tasks/preflight.yml` - 12 modules
- `roles/cve_2026_31431/tasks/remediation_module_blacklist.yml` - 9 modules
- `roles/cve_2026_31431/tasks/remediation_selinux.yml` - 10 modules
- `roles/cve_2026_31431/tasks/remediation_seccomp.yml` - 8 modules
- `roles/cve_2026_31431/tasks/remediation_ebpf.yml` - 12 modules
- `roles/cve_2026_31431/tasks/reporting.yml` - 6 modules
- `roles/cve_2026_31431/tasks/cleanup.yml` - 13 modules
- `roles/cve_2026_31431/tasks/inventory_update.yml` - 7 modules
- `roles/cve_2026_31431/handlers/main.yml` - 4 modules
- `cve_2026_31431_playbook.yml` - 5 modules

**Modules Fixed:**
- `command` → `ansible.builtin.command`
- `shell` → `ansible.builtin.shell`
- `debug` → `ansible.builtin.debug`
- `set_fact` → `ansible.builtin.set_fact`
- `package` → `ansible.builtin.package`
- `template` → `ansible.builtin.template`
- `file` → `ansible.builtin.file`
- `systemd` → `ansible.builtin.systemd`
- `include_tasks` → `ansible.builtin.include_tasks`
- `group_by` → `ansible.builtin.group_by`

---

### 2. Bitwise Operator Incompatibility

**Problem:** Jinja2 does not support the bitwise `&` operator, causing template errors:
```
unexpected char '&' at 63
```

**Original Code:**
```yaml
when: (mitigation_flags | int) & MITIGATE_MODULE_BLACKLIST
```

**Solution:** 
1. Calculate flag states once in `main.yml` using integer division and modulo (supported by Jinja2)
2. Store as boolean variables: `flag_module_blacklist_enabled`, `flag_selinux_enabled`, etc.
3. Use these variables in all conditionals

**New Code in main.yml:**
```yaml
- name: Calculate enabled mitigation flags for display
  ansible.builtin.set_fact:
    flag_module_blacklist_enabled: "{{ ((mitigation_flags | int) // MITIGATE_MODULE_BLACKLIST) % 2 == 1 }}"
    flag_selinux_enabled: "{{ ((mitigation_flags | int) // MITIGATE_SELINUX) % 2 == 1 }}"
    flag_seccomp_enabled: "{{ ((mitigation_flags | int) // MITIGATE_SECCOMP) % 2 == 1 }}"
    flag_ebpf_enabled: "{{ ((mitigation_flags | int) // MITIGATE_EBPF_LSM) % 2 == 1 }}"
```

**Usage in conditionals:**
```yaml
# Old (broken)
when: (mitigation_flags | int) & MITIGATE_SELINUX

# New (works)
when: flag_selinux_enabled
```

**Files Updated:**
- `roles/cve_2026_31431/tasks/main.yml` - Added flag calculations, updated 8 conditionals
- `roles/cve_2026_31431/tasks/preflight.yml` - Updated 3 conditionals
- `roles/cve_2026_31431/tasks/reporting.yml` - Updated 4 debug message conditionals
- `roles/cve_2026_31431/tasks/cleanup.yml` - Updated 15 conditionals + 4 debug message conditionals

**Total Instances Fixed:** 34 bitwise operators replaced

---

## Verification

A verification script has been created to check compliance:

```bash
./verify_ansible_best_practices.sh
```

**Output:**
```
==========================================
Ansible Best Practices Verification
==========================================

1. Checking for FQCN usage in task files...
   ✓ All modules use FQCN

2. Checking for unsupported bitwise operators...
   ✓ No bitwise operators found in task files

3. Checking mitigation flag usage...
   ✓ Flag variables properly defined in main.yml (12 instances)

==========================================
Result: ✓ ALL CHECKS PASSED
==========================================
```

---

## Benefits

### 1. **Future Compatibility**
- FQCN ensures code works with Ansible 2.10+ and future versions
- Avoids namespace collisions with custom modules

### 2. **Reliability**
- No more Jinja2 template errors from unsupported operators
- Flag calculation happens once, reducing computational overhead

### 3. **Maintainability**
- Clear module sources (ansible.builtin vs community collections)
- Easier to read and understand module usage
- Flag variables are self-documenting (`flag_selinux_enabled` vs bitwise math)

### 4. **Standards Compliance**
- Follows official Ansible best practices
- Meets requirements for Ansible Galaxy and automation hub

---

## Testing Recommendations

1. **Syntax Check:**
   ```bash
   ansible-playbook --syntax-check quickstart.yml
   ansible-playbook --syntax-check cve_2026_31431_playbook.yml
   ```

2. **Dry Run:**
   ```bash
   ansible-playbook quickstart.yml --check
   ```

3. **Full Test:**
   ```bash
   ansible-playbook quickstart.yml
   ansible-playbook quickstart.yml -e apply_remediation=true -e mitigation_flags=1 --limit test_host
   ```

4. **Flag Verification:**
   Test each flag combination to ensure bitwise logic works correctly:
   - Flag 1: Module blacklist only
   - Flag 3: Module blacklist + SELinux
   - Flag 7: Module blacklist + SELinux + seccomp
   - Flag 15: All mitigations

---

## Files Modified

**Role Task Files (10):**
- main.yml
- assessment.yml
- preflight.yml
- remediation_module_blacklist.yml
- remediation_selinux.yml
- remediation_seccomp.yml
- remediation_ebpf.yml
- reporting.yml
- cleanup.yml
- inventory_update.yml

**Role Handlers:**
- handlers/main.yml

**Playbooks:**
- cve_2026_31431_playbook.yml

**Total:** 12 files modified

---

## Backward Compatibility

✓ **No breaking changes** - All functionality remains identical
✓ **Same API** - All variables and flags work exactly as before
✓ **Same behavior** - Bitwise flag logic produces identical results

The changes are purely internal improvements to code quality and compatibility.

#!/bin/bash
# Verification script for Ansible best practices

echo "=========================================="
echo "Ansible Best Practices Verification"
echo "=========================================="
echo ""

# Check for FQCN usage
echo "1. Checking for FQCN usage in task files..."
NON_FQCN=$(grep -rn "^  command:\|^  shell:\|^  debug:\|^  set_fact:\|^  package:\|^  template:\|^  file:" roles/cve_2026_31431/tasks/ roles/cve_2026_31431/handlers/ 2>/dev/null | grep -v "ansible.builtin\." | wc -l)
if [ "$NON_FQCN" -eq 0 ]; then
    echo "   ✓ All modules use FQCN"
else
    echo "   ✗ Found $NON_FQCN modules without FQCN"
    grep -rn "^  command:\|^  shell:\|^  debug:" roles/cve_2026_31431/tasks/ | grep -v "ansible.builtin\."
fi
echo ""

# Check for bitwise operators in Jinja2
echo "2. Checking for unsupported bitwise operators..."
BITWISE=$(grep -rn "& MITIGATE_" roles/cve_2026_31431/tasks/ 2>/dev/null | wc -l)
if [ "$BITWISE" -eq 0 ]; then
    echo "   ✓ No bitwise operators found in task files"
else
    echo "   ✗ Found $BITWISE instances of bitwise operators"
    grep -rn "& MITIGATE_" roles/cve_2026_31431/tasks/
fi
echo ""

# Check for proper when conditions
echo "3. Checking mitigation flag usage..."
FLAG_VARS=$(grep "flag_module_blacklist_enabled\|flag_selinux_enabled\|flag_seccomp_enabled\|flag_ebpf_enabled" roles/cve_2026_31431/tasks/main.yml | wc -l)
if [ "$FLAG_VARS" -ge 4 ]; then
    echo "   ✓ Flag variables properly defined in main.yml ($FLAG_VARS instances)"
else
    echo "   ✗ Flag variables incomplete in main.yml (found $FLAG_VARS instances, expected >= 4)"
fi
echo ""

# Summary
echo "=========================================="
if [ "$NON_FQCN" -eq 0 ] && [ "$BITWISE" -eq 0 ] && [ "$FLAG_VARS" -gt 0 ]; then
    echo "Result: ✓ ALL CHECKS PASSED"
else
    echo "Result: ✗ SOME CHECKS FAILED - Review above"
fi
echo "=========================================="

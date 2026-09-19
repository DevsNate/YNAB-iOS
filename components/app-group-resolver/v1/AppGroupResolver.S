.text
.p2align 2

// Narrow signer App Group resolver component v1.
//
// The main app and both widget processes each contain one stock sequence that
// materializes the hard-coded YNAB App Group and bridges it to NSString. The
// version-locked patch replaces those six instructions with a call here and
// five NOPs. The following stock `mov x26, x0` and release remain intact.
//
// The resolver reads the current process' signed App Group entitlement,
// selects the lexicographically smallest non-null entry, and returns a +1
// CFString. That ownership is required because the stock caller releases the
// returned NSString. It fails closed when the signer supplies no usable group
// and deliberately never falls back to YNAB's stock App Group.
//
// The builder replaces the nine unique feed3xxx words with BL instructions to
// the target image's existing dlopen/dlsym stubs.

.globl _ynab_sn_resolve_group
_ynab_sn_resolve_group:
    stp x29, x30, [sp, #-0x70]!
    mov x29, sp
    stp x19, x20, [sp, #0x10]
    stp x21, x22, [sp, #0x20]
    stp x23, x24, [sp, #0x30]
    stp x25, x26, [sp, #0x40]
    stp x27, x28, [sp, #0x50]

    // Make the private SecTask exports available in every extension process.
    adr x0, L_security_path
    mov w1, #1                 // RTLD_LAZY
    .long 0xfeed3001           // BL existing dlopen stub
    cbz x0, L_fail
    mov x19, x0

    mov x0, x19
    adr x1, L_sym_SecTaskCreateFromSelf
    .long 0xfeed3002           // BL existing dlsym stub
    cbz x0, L_fail
    str x0, [sp, #0x60]

    mov x0, x19
    adr x1, L_sym_SecTaskCopyValueForEntitlement
    .long 0xfeed3003
    cbz x0, L_fail
    mov x20, x0

    mov x0, #-2                // RTLD_DEFAULT
    adr x1, L_sym_CFStringCreateWithCString
    .long 0xfeed3004
    cbz x0, L_fail
    mov x21, x0

    mov x0, #-2
    adr x1, L_sym_CFArrayGetCount
    .long 0xfeed3005
    cbz x0, L_fail
    mov x22, x0

    mov x0, #-2
    adr x1, L_sym_CFArrayGetValueAtIndex
    .long 0xfeed3006
    cbz x0, L_fail
    mov x23, x0

    mov x0, #-2
    adr x1, L_sym_CFStringCompare
    .long 0xfeed3007
    cbz x0, L_fail
    mov x24, x0

    mov x0, #-2
    adr x1, L_sym_CFRetain
    .long 0xfeed3008
    cbz x0, L_fail
    mov x25, x0

    mov x0, #-2
    adr x1, L_sym_CFRelease
    .long 0xfeed3009
    cbz x0, L_fail
    mov x26, x0

    // SecTaskCreateFromSelf(NULL). The allocator argument is required.
    ldr x8, [sp, #0x60]
    mov x0, #0
    blr x8
    cbz x0, L_fail
    mov x19, x0

    // Build the entitlement-name CFString.
    mov x0, #0
    adr x1, L_entitlement_app_groups
    mov w2, #0x0100
    movk w2, #0x0800, lsl #16 // kCFStringEncodingUTF8
    blr x21
    cbz x0, L_cleanup_task_fail
    mov x21, x0

    // Copy the current process' application-groups entitlement.
    mov x0, x19
    mov x1, x21
    mov x2, #0
    blr x20
    cbz x0, L_cleanup_key_task_fail
    mov x20, x0

    mov x0, x20
    blr x22
    cmp x0, #1
    b.lt L_cleanup_all_fail
    mov x22, x0

    mov x0, x20
    mov x1, #0
    blr x23
    cbz x0, L_cleanup_all_fail
    mov x27, x0
    mov x28, #1

L_loop:
    cmp x28, x22
    b.ge L_selected
    mov x0, x20
    mov x1, x28
    blr x23
    cbz x0, L_next
    mov x8, x0
    mov x0, x8
    mov x1, x27
    mov x2, #0
    blr x24
    cmp w0, #0
    b.ge L_next
    // The comparison may clobber x8, so fetch the selected value again.
    mov x0, x20
    mov x1, x28
    blr x23
    mov x27, x0
L_next:
    add x28, x28, #1
    b L_loop

L_selected:
    // Balance the stock caller's objc_release of the returned NSString.
    mov x0, x27
    blr x25
    mov x27, x0

    mov x0, x20
    blr x26
    mov x0, x21
    blr x26
    mov x0, x19
    blr x26
    mov x0, x27
    b L_done

L_cleanup_all_fail:
    mov x0, x20
    blr x26
L_cleanup_key_task_fail:
    mov x0, x21
    blr x26
L_cleanup_task_fail:
    mov x0, x19
    blr x26
L_fail:
    mov x0, #0

L_done:
    ldp x27, x28, [sp, #0x50]
    ldp x25, x26, [sp, #0x40]
    ldp x23, x24, [sp, #0x30]
    ldp x21, x22, [sp, #0x20]
    ldp x19, x20, [sp, #0x10]
    ldp x29, x30, [sp], #0x70
    ret

.p2align 3
L_security_path:
    .asciz "/System/Library/Frameworks/Security.framework/Security"
L_sym_SecTaskCreateFromSelf:
    .asciz "SecTaskCreateFromSelf"
L_sym_SecTaskCopyValueForEntitlement:
    .asciz "SecTaskCopyValueForEntitlement"
L_sym_CFStringCreateWithCString:
    .asciz "CFStringCreateWithCString"
L_sym_CFArrayGetCount:
    .asciz "CFArrayGetCount"
L_sym_CFArrayGetValueAtIndex:
    .asciz "CFArrayGetValueAtIndex"
L_sym_CFStringCompare:
    .asciz "CFStringCompare"
L_sym_CFRetain:
    .asciz "CFRetain"
L_sym_CFRelease:
    .asciz "CFRelease"
L_entitlement_app_groups:
    .asciz "com.apple.security.application-groups"

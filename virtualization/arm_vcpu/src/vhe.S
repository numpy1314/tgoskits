// SPDX-License-Identifier: Apache-2.0
// VHE: E2H is never cleared. Guest EL1 registers use EL12 aliases.
.arch armv8.1-a
.section .text.axvisor_vhe_switch,"ax"
.balign 16
.global axvisor_vhe_switch
.type axvisor_vhe_switch, %function
axvisor_vhe_switch:
    sub sp, sp, #320
    str x0, [sp]
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    stp x29, x30, [sp, #96]
    mrs x9, sp_el0
    str x9, [sp, #112]
    mrs x9, tpidr_el0
    str x9, [sp, #120]
    mrs x9, tpidrro_el0
    str x9, [sp, #128]
    mrs x9, vbar_el2
    str x9, [sp, #136]
    mrs x9, hcr_el2
    str x9, [sp, #144]
    mrs x9, cptr_el2
    str x9, [sp, #152]
    mrs x9, cnthctl_el2
    str x9, [sp, #160]
    mrs x9, cntvoff_el2
    str x9, [sp, #168]
    mrs x9, vtcr_el2
    str x9, [sp, #176]
    mrs x9, vttbr_el2
    str x9, [sp, #184]
    mrs x9, mdcr_el2
    str x9, [sp, #192]
    mrs x9, mdscr_el1
    str x9, [sp, #200]
    mrs x9, ich_hcr_el2
    str x9, [sp, #208]
    mrs x9, ich_vmcr_el2
    str x9, [sp, #216]
    mrs x9, icc_sre_el1
    str x9, [sp, #224]
    mrs x9, hstr_el2
    str x9, [sp, #232]
    mrs x9, vpidr_el2
    str x9, [sp, #240]
    mrs x9, vmpidr_el2
    str x9, [sp, #248]
    mrs x9, par_el1
    str x9, [sp, #256]
    mrs x9, elr_el2
    str x9, [sp, #264]
    mrs x9, spsr_el2
    str x9, [sp, #272]
    mrs x9, esr_el2
    str x9, [sp, #280]
    mrs x9, far_el2
    str x9, [sp, #288]
    mrs x9, hpfar_el2
    str x9, [sp, #296]
    mrs x9, actlr_el1
    str x9, [sp, #304]
    mov x19, x0
    // Guest system registers cannot affect the EL2 host translation.
    ldr x9, [x19, #272]
    msr sp_el1, x9
    ldr x9, [x19, #280]
    msr elr_el12, x9
    ldr x9, [x19, #288]
    msr spsr_el12, x9
    ldr x9, [x19, #296]
    msr sctlr_el12, x9
    ldr x9, [x19, #304]
    msr cpacr_el12, x9
    ldr x9, [x19, #312]
    msr ttbr0_el12, x9
    ldr x9, [x19, #320]
    msr ttbr1_el12, x9
    ldr x9, [x19, #328]
    msr tcr_el12, x9
    ldr x9, [x19, #336]
    msr esr_el12, x9
    ldr x9, [x19, #344]
    msr far_el12, x9
    ldr x9, [x19, #352]
    msr mair_el12, x9
    ldr x9, [x19, #360]
    msr amair_el12, x9
    ldr x9, [x19, #368]
    msr vbar_el12, x9
    ldr x9, [x19, #376]
    msr contextidr_el12, x9
    ldr x9, [x19, #384]
    msr tpidr_el1, x9
    ldr x9, [x19, #392]
    msr tpidr_el0, x9
    ldr x9, [x19, #400]
    msr tpidrro_el0, x9
    ldr x9, [x19, #408]
    msr par_el1, x9
    ldr x9, [x19, #416]
    msr cntkctl_el12, x9
    ldr x9, [x19, #424]
    msr mdscr_el1, x9
    ldr x9, [x19, #440]
    msr afsr0_el12, x9
    ldr x9, [x19, #1256]
    msr afsr1_el12, x9
    ldp q0, q1, [x19, #448]
    ldp q2, q3, [x19, #480]
    ldp q4, q5, [x19, #512]
    ldp q6, q7, [x19, #544]
    ldp q8, q9, [x19, #576]
    ldp q10, q11, [x19, #608]
    ldp q12, q13, [x19, #640]
    ldp q14, q15, [x19, #672]
    ldp q16, q17, [x19, #704]
    ldp q18, q19, [x19, #736]
    ldp q20, q21, [x19, #768]
    ldp q22, q23, [x19, #800]
    ldp q24, q25, [x19, #832]
    ldp q26, q27, [x19, #864]
    ldp q28, q29, [x19, #896]
    ldp q30, q31, [x19, #928]
    ldr x9, [x19, #960]
    ldr x10, [x19, #968]
    msr fpcr, x9
    msr fpsr, x10
    ldr x9, [x19, #984]
    msr vtcr_el2, x9
    ldr x9, [x19, #976]
    msr vttbr_el2, x9
    ldr x9, [x19, #992]
    msr vmpidr_el2, x9
    mrs x9, midr_el1
    msr vpidr_el2, x9
    msr hstr_el2, xzr
    mov x9, #0x360
    msr mdcr_el2, x9
    mov x9, #(3 << 20)
    msr cptr_el2, x9
    mov x9, #0x400
    msr cnthctl_el2, x9
    ldr x9, [x19, #1048]
    msr cntvoff_el2, x9
    // CNTV trapping requires ECV, which baseline VHE need not implement.
    // Keep the guest timer in its EL1 bank; sample it on every exit and
    // deliver PPI 27 through the virtual GIC. No physical GIC ownership.
    ldr x9, [x19, #1032]
    msr cntv_cval_el02, x9
    ldr x9, [x19, #1040]
    msr cntv_ctl_el02, x9
    msr cntp_ctl_el02, xzr
    // Direct GICv3 virtual CPU interface, no physical interrupt acknowledgement.
    mov x9, #1
    msr icc_sre_el1, x9
    isb
    ldr x9, [x19, #1184]
    msr ich_vmcr_el2, x9
    mrs x11, ich_vtr_el2
    and x11, x11, #31
    add x11, x11, #1
    cmp x11, #1
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1056]
    msr ich_lr0_el2, x9
    cmp x11, #2
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1064]
    msr ich_lr1_el2, x9
    cmp x11, #3
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1072]
    msr ich_lr2_el2, x9
    cmp x11, #4
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1080]
    msr ich_lr3_el2, x9
    cmp x11, #5
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1088]
    msr ich_lr4_el2, x9
    cmp x11, #6
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1096]
    msr ich_lr5_el2, x9
    cmp x11, #7
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1104]
    msr ich_lr6_el2, x9
    cmp x11, #8
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1112]
    msr ich_lr7_el2, x9
    cmp x11, #9
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1120]
    msr ich_lr8_el2, x9
    cmp x11, #10
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1128]
    msr ich_lr9_el2, x9
    cmp x11, #11
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1136]
    msr ich_lr10_el2, x9
    cmp x11, #12
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1144]
    msr ich_lr11_el2, x9
    cmp x11, #13
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1152]
    msr ich_lr12_el2, x9
    cmp x11, #14
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1160]
    msr ich_lr13_el2, x9
    cmp x11, #15
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1168]
    msr ich_lr14_el2, x9
    cmp x11, #16
    b.lo .Lloaded_lrs
    ldr x9, [x19, #1176]
    msr ich_lr15_el2, x9
.Lloaded_lrs:
    mrs x11, ich_vtr_el2
    ubfx x11, x11, #29, #3
    ldr x9, [x19, #1192]
    msr ich_ap0r0_el2, x9
    ldr x9, [x19, #1224]
    msr ich_ap1r0_el2, x9
    cmp x11, #5
    b.lo .Lloaded_aprs
    ldr x9, [x19, #1200]
    msr ich_ap0r1_el2, x9
    ldr x9, [x19, #1232]
    msr ich_ap1r1_el2, x9
    cmp x11, #6
    b.lo .Lloaded_aprs
    ldr x9, [x19, #1208]
    msr ich_ap0r2_el2, x9
    ldr x9, [x19, #1240]
    msr ich_ap1r2_el2, x9
    cmp x11, #6
    b.lo .Lloaded_aprs
    ldr x9, [x19, #1216]
    msr ich_ap0r3_el2, x9
    ldr x9, [x19, #1248]
    msr ich_ap1r3_el2, x9
.Lloaded_aprs:
    mov x9, #1
    msr ich_hcr_el2, x9
    adr x9, axvisor_vhe_vectors
    msr vbar_el2, x9
    // VM, SWIO, PTW, FMO/IMO/AMO, FB, BSU_IS, TWI/TWE, TID2/3,
    // TSC, TACR, TIDCP, TSW, RW and E2H. Host cache/debug controls stay trapped.
    movz x9, #0x663f
    movk x9, #0x807e, lsl #16
    movk x9, #4, lsl #32
    msr hcr_el2, x9
    isb
    // Conservative VMID-0 policy: invalidate the entire local guest context
    // on every entry, after selecting guest translation with TGE=0.
    dsb ish
    tlbi vmalls12e1
    ic iallu
    dsb ish
    isb
    ldr x9, [x19, #248]
    msr sp_el0, x9
    ldp x9, x10, [x19, #256]
    msr elr_el2, x9
    msr spsr_el2, x10
    mov x30, x19
    ldp x0, x1, [x30, #0]
    ldp x2, x3, [x30, #16]
    ldp x4, x5, [x30, #32]
    ldp x6, x7, [x30, #48]
    ldp x8, x9, [x30, #64]
    ldp x10, x11, [x30, #80]
    ldp x12, x13, [x30, #96]
    ldp x14, x15, [x30, #112]
    ldp x16, x17, [x30, #128]
    ldp x18, x19, [x30, #144]
    ldp x20, x21, [x30, #160]
    ldp x22, x23, [x30, #176]
    ldp x24, x25, [x30, #192]
    ldp x26, x27, [x30, #208]
    ldp x28, x29, [x30, #224]
    ldr x30, [x30, #240]
    eret
.size axvisor_vhe_switch, .-axvisor_vhe_switch
.balign 2048
axvisor_vhe_vectors:
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #16
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #17
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #18
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #19
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #20
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #21
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #22
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #23
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #0
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #1
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #2
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #3
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #28
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #29
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #30
    b .Lvhe_exit
    .balign 128
    stp x0, x1, [sp, #-16]!
    mov x0, #31
    b .Lvhe_exit
.balign 16
.Lvhe_exit:
    ldr x1, [sp, #16]
    str x0, [x1, #1024]
    stp x2, x3, [x1, #16]
    stp x4, x5, [x1, #32]
    stp x6, x7, [x1, #48]
    stp x8, x9, [x1, #64]
    stp x10, x11, [x1, #80]
    stp x12, x13, [x1, #96]
    stp x14, x15, [x1, #112]
    stp x16, x17, [x1, #128]
    stp x18, x19, [x1, #144]
    stp x20, x21, [x1, #160]
    stp x22, x23, [x1, #176]
    stp x24, x25, [x1, #192]
    stp x26, x27, [x1, #208]
    stp x28, x29, [x1, #224]
    str x30, [x1, #240]
    ldp x9, x10, [sp], #16
    stp x9, x10, [x1]
    mov x19, x1
    mrs x9, sp_el0
    str x9, [x19, #248]
    mrs x9, elr_el2
    str x9, [x19, #256]
    mrs x9, spsr_el2
    str x9, [x19, #264]
    mrs x9, esr_el2
    str x9, [x19, #1000]
    mrs x9, far_el2
    str x9, [x19, #1008]
    mrs x9, hpfar_el2
    str x9, [x19, #1016]
    mrs x9, sp_el1
    str x9, [x19, #272]
    mrs x9, elr_el12
    str x9, [x19, #280]
    mrs x9, spsr_el12
    str x9, [x19, #288]
    mrs x9, sctlr_el12
    str x9, [x19, #296]
    mrs x9, cpacr_el12
    str x9, [x19, #304]
    mrs x9, ttbr0_el12
    str x9, [x19, #312]
    mrs x9, ttbr1_el12
    str x9, [x19, #320]
    mrs x9, tcr_el12
    str x9, [x19, #328]
    mrs x9, esr_el12
    str x9, [x19, #336]
    mrs x9, far_el12
    str x9, [x19, #344]
    mrs x9, mair_el12
    str x9, [x19, #352]
    mrs x9, amair_el12
    str x9, [x19, #360]
    mrs x9, vbar_el12
    str x9, [x19, #368]
    mrs x9, contextidr_el12
    str x9, [x19, #376]
    mrs x9, tpidr_el1
    str x9, [x19, #384]
    mrs x9, tpidr_el0
    str x9, [x19, #392]
    mrs x9, tpidrro_el0
    str x9, [x19, #400]
    mrs x9, par_el1
    str x9, [x19, #408]
    mrs x9, cntkctl_el12
    str x9, [x19, #416]
    mrs x9, mdscr_el1
    str x9, [x19, #424]
    mrs x9, afsr0_el12
    str x9, [x19, #440]
    mrs x9, afsr1_el12
    str x9, [x19, #1256]
    stp q0, q1, [x19, #448]
    stp q2, q3, [x19, #480]
    stp q4, q5, [x19, #512]
    stp q6, q7, [x19, #544]
    stp q8, q9, [x19, #576]
    stp q10, q11, [x19, #608]
    stp q12, q13, [x19, #640]
    stp q14, q15, [x19, #672]
    stp q16, q17, [x19, #704]
    stp q18, q19, [x19, #736]
    stp q20, q21, [x19, #768]
    stp q22, q23, [x19, #800]
    stp q24, q25, [x19, #832]
    stp q26, q27, [x19, #864]
    stp q28, q29, [x19, #896]
    stp q30, q31, [x19, #928]
    mrs x9, fpcr
    mrs x10, fpsr
    str x9, [x19, #960]
    str x10, [x19, #968]
    mrs x9, cntv_cval_el02
    str x9, [x19, #1032]
    mrs x9, cntv_ctl_el02
    and x9, x9, #3
    str x9, [x19, #1040]
    msr cntv_ctl_el02, xzr
    msr ich_hcr_el2, xzr
    mrs x9, ich_vmcr_el2
    str x9, [x19, #1184]
    mrs x11, ich_vtr_el2
    and x11, x11, #31
    add x11, x11, #1
    cmp x11, #1
    b.lo .Lsaved_lrs
    mrs x9, ich_lr0_el2
    str x9, [x19, #1056]
    msr ich_lr0_el2, xzr
    cmp x11, #2
    b.lo .Lsaved_lrs
    mrs x9, ich_lr1_el2
    str x9, [x19, #1064]
    msr ich_lr1_el2, xzr
    cmp x11, #3
    b.lo .Lsaved_lrs
    mrs x9, ich_lr2_el2
    str x9, [x19, #1072]
    msr ich_lr2_el2, xzr
    cmp x11, #4
    b.lo .Lsaved_lrs
    mrs x9, ich_lr3_el2
    str x9, [x19, #1080]
    msr ich_lr3_el2, xzr
    cmp x11, #5
    b.lo .Lsaved_lrs
    mrs x9, ich_lr4_el2
    str x9, [x19, #1088]
    msr ich_lr4_el2, xzr
    cmp x11, #6
    b.lo .Lsaved_lrs
    mrs x9, ich_lr5_el2
    str x9, [x19, #1096]
    msr ich_lr5_el2, xzr
    cmp x11, #7
    b.lo .Lsaved_lrs
    mrs x9, ich_lr6_el2
    str x9, [x19, #1104]
    msr ich_lr6_el2, xzr
    cmp x11, #8
    b.lo .Lsaved_lrs
    mrs x9, ich_lr7_el2
    str x9, [x19, #1112]
    msr ich_lr7_el2, xzr
    cmp x11, #9
    b.lo .Lsaved_lrs
    mrs x9, ich_lr8_el2
    str x9, [x19, #1120]
    msr ich_lr8_el2, xzr
    cmp x11, #10
    b.lo .Lsaved_lrs
    mrs x9, ich_lr9_el2
    str x9, [x19, #1128]
    msr ich_lr9_el2, xzr
    cmp x11, #11
    b.lo .Lsaved_lrs
    mrs x9, ich_lr10_el2
    str x9, [x19, #1136]
    msr ich_lr10_el2, xzr
    cmp x11, #12
    b.lo .Lsaved_lrs
    mrs x9, ich_lr11_el2
    str x9, [x19, #1144]
    msr ich_lr11_el2, xzr
    cmp x11, #13
    b.lo .Lsaved_lrs
    mrs x9, ich_lr12_el2
    str x9, [x19, #1152]
    msr ich_lr12_el2, xzr
    cmp x11, #14
    b.lo .Lsaved_lrs
    mrs x9, ich_lr13_el2
    str x9, [x19, #1160]
    msr ich_lr13_el2, xzr
    cmp x11, #15
    b.lo .Lsaved_lrs
    mrs x9, ich_lr14_el2
    str x9, [x19, #1168]
    msr ich_lr14_el2, xzr
    cmp x11, #16
    b.lo .Lsaved_lrs
    mrs x9, ich_lr15_el2
    str x9, [x19, #1176]
    msr ich_lr15_el2, xzr
.Lsaved_lrs:
    mrs x11, ich_vtr_el2
    ubfx x11, x11, #29, #3
    mrs x9, ich_ap0r0_el2
    str x9, [x19, #1192]
    msr ich_ap0r0_el2, xzr
    mrs x9, ich_ap1r0_el2
    str x9, [x19, #1224]
    msr ich_ap1r0_el2, xzr
    cmp x11, #5
    b.lo .Lsaved_aprs
    mrs x9, ich_ap0r1_el2
    str x9, [x19, #1200]
    msr ich_ap0r1_el2, xzr
    mrs x9, ich_ap1r1_el2
    str x9, [x19, #1232]
    msr ich_ap1r1_el2, xzr
    cmp x11, #6
    b.lo .Lsaved_aprs
    mrs x9, ich_ap0r2_el2
    str x9, [x19, #1208]
    msr ich_ap0r2_el2, xzr
    mrs x9, ich_ap1r2_el2
    str x9, [x19, #1240]
    msr ich_ap1r2_el2, xzr
    cmp x11, #6
    b.lo .Lsaved_aprs
    mrs x9, ich_ap0r3_el2
    str x9, [x19, #1216]
    msr ich_ap0r3_el2, xzr
    mrs x9, ich_ap1r3_el2
    str x9, [x19, #1248]
    msr ich_ap1r3_el2, xzr
.Lsaved_aprs:
    // Restore the complete host view before any host callback/IRQ can run.
    dsb ish
    ldr x9, [sp, #144]
    msr hcr_el2, x9
    isb
    ldr x9, [sp, #112]
    msr sp_el0, x9
    ldr x9, [sp, #120]
    msr tpidr_el0, x9
    ldr x9, [sp, #128]
    msr tpidrro_el0, x9
    ldr x9, [sp, #136]
    msr vbar_el2, x9
    ldr x9, [sp, #152]
    msr cptr_el2, x9
    ldr x9, [sp, #160]
    msr cnthctl_el2, x9
    ldr x9, [sp, #168]
    msr cntvoff_el2, x9
    ldr x9, [sp, #176]
    msr vtcr_el2, x9
    ldr x9, [sp, #184]
    msr vttbr_el2, x9
    ldr x9, [sp, #192]
    msr mdcr_el2, x9
    ldr x9, [sp, #200]
    msr mdscr_el1, x9
    ldr x9, [sp, #208]
    msr ich_hcr_el2, x9
    ldr x9, [sp, #216]
    msr ich_vmcr_el2, x9
    ldr x9, [sp, #224]
    msr icc_sre_el1, x9
    ldr x9, [sp, #232]
    msr hstr_el2, x9
    ldr x9, [sp, #240]
    msr vpidr_el2, x9
    ldr x9, [sp, #248]
    msr vmpidr_el2, x9
    isb
    ldr x9, [sp, #256]
    msr par_el1, x9
    ldr x9, [sp, #264]
    msr elr_el2, x9
    ldr x9, [sp, #272]
    msr spsr_el2, x9
    ldr x9, [sp, #280]
    msr esr_el2, x9
    ldr x9, [sp, #288]
    msr far_el2, x9
    ldr x9, [sp, #296]
    msr hpfar_el2, x9
    ldr x9, [sp, #304]
    msr actlr_el1, x9
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp, #96]
    add sp, sp, #320
    ret

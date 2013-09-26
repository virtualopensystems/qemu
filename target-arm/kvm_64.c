/*
 * ARM implementation of KVM hooks for AARCH64
 *
 * Copyright Christoffer Dall 2009-2010
 *           Mian-M. Hamayun 2013, Virtual Open Systems
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <stdio.h>
#include <sys/types.h>

#include <linux/kvm.h>

#include "qemu-common.h"
#include "sysemu/kvm.h"
#include "kvm_arm.h"

#define AARCH64_CORE_REG(x) (KVM_REG_ARM64 | KVM_REG_SIZE_U64 | \
                            KVM_REG_ARM_CORE | KVM_REG_ARM_CORE_REG(x))

static uint32_t kvm_arm_targets[KVM_ARM_NUM_TARGETS] = {
    KVM_ARM_TARGET_AEM_V8,
    KVM_ARM_TARGET_FOUNDATION_V8,
    KVM_ARM_TARGET_CORTEX_A57
};

int kvm_arch_init_vcpu(CPUState *cs)
{
    struct kvm_vcpu_init init;
    int ret, i;

    memset(init.features, 0, sizeof(init.features));
    /* Find an appropriate target CPU type.
     * KVM does not provide means to detect the host CPU type on aarch64,
     * and simply refuses to initialize, if the CPU type mis-matches;
     * so we try each possible CPU type on aarch64 before giving up! */
    for (i = 0; i < KVM_ARM_NUM_TARGETS; ++i) {
        init.target = kvm_arm_targets[i];
        ret = kvm_vcpu_ioctl(cs, KVM_ARM_VCPU_INIT, &init);
        if (!ret)
            break;
    }

    return ret;
}

int kvm_arch_put_registers(CPUState *cs, int level)
{
    struct kvm_one_reg reg;
    int i;
    int ret;

    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    for (i = 0; i < ARRAY_SIZE(env->xregs); i++) {
        reg.id = AARCH64_CORE_REG(regs.regs[i]);
        reg.addr = (uintptr_t) &env->xregs[i];
        ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
        if (ret) {
            return ret;
        }
    }

    reg.id = AARCH64_CORE_REG(regs.sp);
    reg.addr = (uintptr_t) &env->xregs[31];
    ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
    if (ret) {
        return ret;
    }

    reg.id = AARCH64_CORE_REG(regs.pstate);
    reg.addr = (uintptr_t) &env->pstate;
    ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
    if (ret) {
        return ret;
    }

    reg.id = AARCH64_CORE_REG(regs.pc);
    reg.addr = (uintptr_t) &env->pc;
    ret = kvm_vcpu_ioctl(cs, KVM_SET_ONE_REG, &reg);
    if (ret) {
        return ret;
    }

    /* TODO: Set Rest of Registers */
    return ret;
}

int kvm_arch_get_registers(CPUState *cs)
{
    struct kvm_one_reg reg;
    int i;
    int ret;

    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    for (i = 0; i < ARRAY_SIZE(env->xregs); i++) {
        reg.id = AARCH64_CORE_REG(regs.regs[i]);
        reg.addr = (uintptr_t) &env->xregs[i];
        ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
        if (ret) {
            return ret;
        }
    }

    reg.id = AARCH64_CORE_REG(regs.sp);
    reg.addr = (uintptr_t) &env->xregs[31];
    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
    if (ret) {
        return ret;
    }

    reg.id = AARCH64_CORE_REG(regs.pstate);
    reg.addr = (uintptr_t) &env->pstate;
    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
    if (ret) {
        return ret;
    }

    reg.id = AARCH64_CORE_REG(regs.pc);
    reg.addr = (uintptr_t) &env->pc;
    ret = kvm_vcpu_ioctl(cs, KVM_GET_ONE_REG, &reg);
    if (ret) {
        return ret;
    }

    /* TODO: Set Rest of Registers */
    return ret;
}

void kvm_arch_reset_vcpu(CPUState *cs)
{
}


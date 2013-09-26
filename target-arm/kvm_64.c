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

int kvm_arch_init_vcpu(CPUState *cs)
{
    return 0;
}

int kvm_arch_put_registers(CPUState *cs, int level)
{
    return 0;
}

int kvm_arch_get_registers(CPUState *cs)
{
    return 0;
}

void kvm_arch_reset_vcpu(CPUState *cs)
{
}


/*
 * Cortex-A57MPCore internal peripheral emulation.
 *
 * Copyright (c) 2012 Linaro Limited.
 * Written by Peter Maydell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "hw/sysbus.h"
#include "sysemu/kvm.h"

/* A57MP private memory region.  */

#define TYPE_A57MPCORE_PRIV "a57mpcore_priv"
#define A57MPCORE_PRIV(obj) \
    OBJECT_CHECK(A57MPPrivState, (obj), TYPE_A57MPCORE_PRIV)

typedef struct A57MPPrivState {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/

    uint32_t num_cpu;
    uint32_t num_irq;
    MemoryRegion container;
    DeviceState *gic;
} A57MPPrivState;

static void a57mp_priv_set_irq(void *opaque, int irq, int level)
{
    A57MPPrivState *s = (A57MPPrivState *)opaque;
    qemu_set_irq(qdev_get_gpio_in(s->gic, irq), level);
}

static int a57mp_priv_init(SysBusDevice *dev)
{
    A57MPPrivState *s = A57MPCORE_PRIV(dev);
    SysBusDevice *busdev;
    const char *gictype = "arm_gic";

    if (kvm_irqchip_in_kernel()) {
        gictype = "kvm-arm-gic";
    }

    s->gic = qdev_create(NULL, gictype);
    qdev_prop_set_uint32(s->gic, "num-cpu", s->num_cpu);
    qdev_prop_set_uint32(s->gic, "num-irq", s->num_irq);
    qdev_prop_set_uint32(s->gic, "revision", 2);
    qdev_init_nofail(s->gic);
    busdev = SYS_BUS_DEVICE(s->gic);

    /* Pass through outbound IRQ lines from the GIC */
    sysbus_pass_irq(dev, busdev);

    /* Pass through inbound GPIO lines to the GIC */
    qdev_init_gpio_in(DEVICE(dev), a57mp_priv_set_irq, s->num_irq - 32);

    /* Memory map (addresses are offsets from PERIPHBASE):
     *  0x0000-0x0fff -- reserved
     *  0x1000-0x1fff -- GIC Distributor
     *  0x2000-0x2fff -- GIC CPU interface
     *  0x4000-0x4fff -- GIC virtual interface control (not modelled)
     *  0x5000-0x5fff -- GIC virtual interface control (not modelled)
     *  0x6000-0x7fff -- GIC virtual CPU interface (not modelled)
     */
    memory_region_init(&s->container, OBJECT(s),
                       "a57mp-priv-container", 0x8000);
    memory_region_add_subregion(&s->container, 0x1000,
                                sysbus_mmio_get_region(busdev, 0));
    memory_region_add_subregion(&s->container, 0x2000,
                                sysbus_mmio_get_region(busdev, 1));

    sysbus_init_mmio(dev, &s->container);
    return 0;
}

static Property a57mp_priv_properties[] = {
    DEFINE_PROP_UINT32("num-cpu", A57MPPrivState, num_cpu, 1),
    /* The Cortex-A57MP may have anything from 0 to 224 external interrupt
     * IRQ lines (with another 32 internal). We default to 128+32, which
     * is the number provided by the Cortex-A57MP test chip in the
     * Versatile Express A57 development board.
     * Other boards may differ and should set this property appropriately.
     */
    DEFINE_PROP_UINT32("num-irq", A57MPPrivState, num_irq, 160),
    DEFINE_PROP_END_OF_LIST(),
};

static void a57mp_priv_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);
    k->init = a57mp_priv_init;
    dc->props = a57mp_priv_properties;
    /* We currently have no savable state */
}

static const TypeInfo a57mp_priv_info = {
    .name  = TYPE_A57MPCORE_PRIV,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size  = sizeof(A57MPPrivState),
    .class_init = a57mp_priv_class_init,
};

static void a57mp_register_types(void)
{
    type_register_static(&a57mp_priv_info);
}

type_init(a57mp_register_types)

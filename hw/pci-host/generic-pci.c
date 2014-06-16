/*
 * Generic PCI host controller
 *
 * Copyright (c) 2014 Linaro, Ltd.
 * Author: Rob Herring <rob.herring@linaro.org>
 *
 * Based on ARM Versatile PCI controller (hw/pci-host/versatile.c):
 * Copyright (c) 2006-2009 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the LGPL.
 */

#include "hw/sysbus.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci/pci_host.h"
#include "exec/address-spaces.h"

typedef struct {
    PCIHostState parent_obj;

    qemu_irq irq[4];
    MemoryRegion mem_config;
    /* Containers representing the PCI address spaces */
    MemoryRegion pci_io_space;
    MemoryRegion pci_mem_space;
    /* Alias regions into PCI address spaces which we expose as sysbus regions.
     * The offsets into pci_mem_space are controlled by the imap registers.
     */
    MemoryRegion pci_io_window;
    MemoryRegion pci_mem_window;
    PCIBus pci_bus;
    PCIDevice pci_dev;
} PCIVPBState;


static const VMStateDescription pci_generic_host_vmstate = {
    .name = "generic-host-pci",
    .version_id = 1,
    .minimum_version_id = 1,
};

#define TYPE_GENERIC_PCI "generic_pci"
#define PCI_GEN(obj) \
    OBJECT_CHECK(PCIVPBState, (obj), TYPE_GENERIC_PCI)

#define TYPE_GENERIC_PCI_HOST "generic_pci_host"
#define PCI_GEN_HOST(obj) \
    OBJECT_CHECK(PCIDevice, (obj), TYPE_GENERIC_PCIHOST)


static void pci_cam_config_write(void *opaque, hwaddr addr,
                                 uint64_t val, unsigned size)
{
    PCIVPBState *s = opaque;
    pci_data_write(&s->pci_bus, addr, val, size);
}

static uint64_t pci_cam_config_read(void *opaque, hwaddr addr, unsigned size)
{
    PCIVPBState *s = opaque;
    uint32_t val;
    val = pci_data_read(&s->pci_bus, addr, size);
    return val;
}

static const MemoryRegionOps pci_vpb_config_ops = {
    .read = pci_cam_config_read,
    .write = pci_cam_config_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void pci_generic_set_irq(void *opaque, int irq_num, int level)
{
    qemu_irq *pic = opaque;
    qemu_set_irq(pic[irq_num], level);
}

static void pci_generic_host_init(Object *obj)
{
    PCIHostState *h = PCI_HOST_BRIDGE(obj);
    PCIVPBState *s = PCI_GEN(obj);

    memory_region_init(&s->pci_io_space, OBJECT(s), "pci_io", 0x10000);
    memory_region_init(&s->pci_mem_space, OBJECT(s), "pci_mem", 1ULL << 32);

    pci_bus_new_inplace(&s->pci_bus, sizeof(s->pci_bus), DEVICE(obj), "pci",
                        &s->pci_mem_space, &s->pci_io_space,
                        PCI_DEVFN(0, 0), TYPE_PCIE_BUS);
    h->bus = &s->pci_bus;

    object_initialize(&s->pci_dev, sizeof(s->pci_dev), TYPE_GENERIC_PCI_HOST);
    qdev_set_parent_bus(DEVICE(&s->pci_dev), BUS(&s->pci_bus));
}

static void pci_generic_host_realize(DeviceState *dev, Error **errp)
{
    PCIVPBState *s = PCI_GEN(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    int i;

    for (i = 0; i < 4; i++) {
        sysbus_init_irq(sbd, &s->irq[i]);
    }

    pci_bus_irqs(&s->pci_bus, pci_generic_set_irq, pci_swizzle_map_irq_fn,
                 s->irq, 4);

    /* Our memory regions are:
     * 0 : PCI config window
     * 1 : PCI IO window
     * 2 : PCI memory windows
     */
    memory_region_init_io(&s->mem_config, OBJECT(s), &pci_vpb_config_ops, s,
                          "pci-config", 0x1000000);
    sysbus_init_mmio(sbd, &s->mem_config);

    /* The window into I/O space is always into a fixed base address;
     * its size is the same for both realview and versatile.
     */
    memory_region_init_alias(&s->pci_io_window, OBJECT(s), "pci-io-win",
                             &s->pci_io_space, 0, 0x10000);
    sysbus_init_mmio(sbd, &s->pci_io_space);

    /* Create the alias regions corresponding to our three windows onto
     * PCI memory space. The sizes vary from board to board; the base
     * offsets are guest controllable via the IMAP registers.
     */
    memory_region_init_alias(&s->pci_mem_window, OBJECT(s), "pci-mem-win",
                             &s->pci_mem_space, 0x12000000, 0x2e000000);
    sysbus_init_mmio(sbd, &s->pci_mem_window);

    /* TODO Remove once realize propagates to child devices. */
    object_property_set_bool(OBJECT(&s->pci_dev), true, "realized", errp);
}

static void pci_generic_host_class_init(ObjectClass *klass, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    k->vendor_id = PCI_VENDOR_ID_REDHAT;
    k->device_id = 0x1234;
    k->class_id = PCI_CLASS_PROCESSOR_CO;
    /*
     * PCI-facing part of the host bridge, not usable without the
     * host-facing part, which can't be device_add'ed, yet.
     */
    dc->cannot_instantiate_with_device_add_yet = true;
}

static const TypeInfo pci_generic_host_info = {
    .name          = TYPE_GENERIC_PCI_HOST,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCIDevice),
    .class_init    = pci_generic_host_class_init,
};

static void pci_generic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = pci_generic_host_realize;
    dc->vmsd = &pci_generic_host_vmstate;
}

static const TypeInfo pci_generic_info = {
    .name          = TYPE_GENERIC_PCI,
    .parent        = TYPE_PCI_HOST_BRIDGE,
    .instance_size = sizeof(PCIVPBState),
    .instance_init = pci_generic_host_init,
    .class_init    = pci_generic_class_init,
};

static void generic_pci_host_register_types(void)
{
    type_register_static(&pci_generic_info);
    type_register_static(&pci_generic_host_info);
}

type_init(generic_pci_host_register_types)

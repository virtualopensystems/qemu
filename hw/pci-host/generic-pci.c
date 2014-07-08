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
#include "hw/pci-host/pci_generic.h"
#include "exec/address-spaces.h"
#include "sysemu/device_tree.h"

static const VMStateDescription pci_generic_host_vmstate = {
    .name = "generic-host-pci",
    .version_id = 1,
    .minimum_version_id = 1,
};

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

    object_initialize(&s->pci_gen, sizeof(s->pci_gen), TYPE_GENERIC_PCI_HOST);
    qdev_set_parent_bus(DEVICE(&s->pci_gen), BUS(&s->pci_bus));
}

static int generic_pci_map_irq_fn(PCIDevice *pci_dev, int pin)
{
    BusState *bus = qdev_get_parent_bus(&pci_dev->qdev);
    PCIBus *pci_bus = PCI_BUS(bus);
    PCIDevice *pdev = pci_bus->devices[PCI_DEVFN(0, 0)];
    GenericPCIHostState *gps = PCI_GEN_HOST(pdev);

    if (!pin) {
        return gps->irqmap.slot_idx_map[PCI_SLOT(pci_dev->devfn)];
    }

    hw_error("generic_pci: only one pin per device supported.");
}

static void pci_generic_host_realize(DeviceState *dev, Error **errp)
{
    PCIVPBState *s = PCI_GEN(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    hwaddr *mapping_data;
    int i;

    for (i = 0; i < MAX_PCI_DEVICES; i++) {
        sysbus_init_irq(sbd, &s->irq[i]);
    }

    pci_bus_irqs(&s->pci_bus, pci_generic_set_irq, generic_pci_map_irq_fn,
                 s->irq, MAX_PCI_DEVICES);

    /* Our memory regions are:
     * 0 : PCI config window
     * 1 : PCI IO window
     * 2 : PCI memory windows
     * The CPU addresses and size of each memory region have been set by the
     * machine code inside s->dt_data.
     */
    mapping_data = s->dt_data.addr_mapping;
    memory_region_init_io(&s->mem_config, OBJECT(s), &pci_vpb_config_ops, s,
                          "pci-config", mapping_data[1]);
    sysbus_init_mmio(sbd, &s->mem_config);

    /* The window into I/O space is always into a fixed base address;
     * its size is the same for both realview and versatile.
     */
    memory_region_init_alias(&s->pci_io_window, OBJECT(s), "pci-io-win",
                    &s->pci_io_space, mapping_data[2], mapping_data[3]);
    sysbus_init_mmio(sbd, &s->pci_io_space);

    /* Create the alias regions corresponding to our three windows onto
     * PCI memory space. The sizes vary from board to board; the base
     * offsets are guest controllable via the IMAP registers.
     */
    memory_region_init_alias(&s->pci_mem_window, OBJECT(s), "pci-mem-win",
                     &s->pci_mem_space, mapping_data[4], mapping_data[5]);
    sysbus_init_mmio(sbd, &s->pci_mem_window);

    /* TODO Remove once realize propagates to child devices. */
    object_property_set_bool(OBJECT(&s->pci_gen), true, "realized", errp);
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

struct dt_irq_mapping {
        DeviceState *dev;
        uint32_t gic_phandle;
        int base_irq_num;
        uint64_t *data;
};

#define IRQ_MAPPING_CELLS 14
/* Generate the irq_mapping data and return the number of the device attached
 * to the device bus.
 * */
static int generate_int_mapping(struct dt_irq_mapping *irq_map, PCIVPBState *s)
{
    BusState *inner_bus;
    BusChild *inner;
    int slot_count = 0;
    uint64_t *data_ptr = irq_map->data;

    QLIST_FOREACH(inner_bus, &irq_map->dev->child_bus, sibling) {
        QTAILQ_FOREACH(inner, &inner_bus->children, sibling) {
            DeviceState *dev = inner->child;
            PCIDevice *pdev = PCI_DEVICE(dev);
            int pci_slot = PCI_SLOT(pdev->devfn);
            uint8_t *slot_idx = s->pci_gen.irqmap.slot_idx_map;
            uint8_t *slot_irq = s->pci_gen.irqmap.slot_irq_map;

            if (slot_count > MAX_PCI_DEVICES) {
                hw_error("generic_pci: too many PCI devices.");
            }

            /* Every PCI slot has one interrupt mapped. */
            slot_idx[pci_slot] = slot_count;
            slot_irq[slot_count] = irq_map->base_irq_num + slot_count;

            uint64_t buffer[IRQ_MAPPING_CELLS] =
            {1, pci_slot << 11, 2, 0x00000000, 1, 0x1,
             1, irq_map->gic_phandle, 1, 0, 1, slot_irq[slot_count],
             1, 0x1};

            memcpy(data_ptr, buffer, IRQ_MAPPING_CELLS * sizeof(*buffer));
            slot_count++;
            data_ptr += IRQ_MAPPING_CELLS;
        }
    }

    return slot_count;
}

static void generate_dt_node(DeviceState *dev)
{
    PCIVPBState *s = PCI_GEN(dev);
    char *nodename;
    uint32_t gic_phandle;
    int num_dev;
    hwaddr *map = s->dt_data.addr_mapping;
    void *fdt = s->dt_data.fdt;

    nodename = g_strdup_printf("/pci@%" PRIx64, map[0]);
    qemu_fdt_add_subnode(fdt, nodename);
    qemu_fdt_setprop_string(fdt, nodename, "compatible",
                            "pci-host-cam-generic");
    qemu_fdt_setprop_string(fdt, nodename, "device_type", "pci");
    qemu_fdt_setprop_cell(fdt, nodename, "#address-cells", 0x3);
    qemu_fdt_setprop_cell(fdt, nodename, "#size-cells", 0x2);
    qemu_fdt_setprop_cell(fdt, nodename, "#interrupt-cells", 0x1);

    /* config space */
    qemu_fdt_setprop_sized_cells(fdt, nodename, "reg", 2, map[0],
                                                            2, map[1]);

    qemu_fdt_setprop_sized_cells(fdt, nodename, "ranges",
         1, 0x01000000, 2, 0x00000000, 2, map[2], 2, map[3],
         1, 0x02000000, 2, 0x12000000, 2, map[4], 2, map[5]);

    gic_phandle = qemu_fdt_get_phandle(fdt, "/intc");
    qemu_fdt_setprop_sized_cells(fdt, nodename, "interrupt-map-mask",
                                  1, 0xf800, 1, 0x0, 1, 0x0, 1, 0x7);

    /* Generate the interrupt mapping according to the devices attached
     * to the PCI bus of the device. */
    uint64_t *int_mapping_data = g_malloc0(IRQ_MAPPING_CELLS * sizeof(uint64_t)
                                                            * MAX_PCI_DEVICES);

    struct dt_irq_mapping dt_map = {
        .dev = dev,
        .gic_phandle = gic_phandle,
        .base_irq_num = s->dt_data.irq_base,
        .data = int_mapping_data
    };

    num_dev = generate_int_mapping(&dt_map, s);
    qemu_fdt_setprop_sized_cells_from_array(fdt, nodename, "interrupt-map",
                        (num_dev * IRQ_MAPPING_CELLS)/2, int_mapping_data);

    g_free(int_mapping_data);
    g_free(nodename);
    /* Once the dt node is created, this data is no longer necessary */
    g_free(s->dt_data.addr_mapping);
}

static const TypeInfo pci_generic_host_info = {
    .name          = TYPE_GENERIC_PCI_HOST,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(GenericPCIHostState),
    .class_init    = pci_generic_host_class_init,
};

static void pci_generic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    GenericPCIClass *pc = GENERIC_PCI_CLASS(klass);

    dc->realize = pci_generic_host_realize;
    dc->vmsd = &pci_generic_host_vmstate;
    pc->gen_dt_node = generate_dt_node;
}

static const TypeInfo pci_generic_info = {
    .name          = TYPE_GENERIC_PCI,
    .parent        = TYPE_PCI_HOST_BRIDGE,
    .instance_size = sizeof(PCIVPBState),
    .instance_init = pci_generic_host_init,
    .class_init    = pci_generic_class_init,
    .class_size    = sizeof(GenericPCIClass),
};

static void generic_pci_host_register_types(void)
{
    type_register_static(&pci_generic_info);
    type_register_static(&pci_generic_host_info);
}

type_init(generic_pci_host_register_types)

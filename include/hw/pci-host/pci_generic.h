#ifndef QEMU_GENERIC_PCI_H
#define QEMU_GENERIC_PCI_H

#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci/pci_host.h"

#define MAX_PCI_DEVICES 10

struct dt_data {
    void *fdt;
    int irq_base;
    hwaddr *addr_mapping;
};

typedef struct {
    PCIHostState parent_obj;

    qemu_irq irq[MAX_PCI_DEVICES];
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
    /* Device tree data set by the machine
     */
    struct dt_data dt_data;
} PCIVPBState;

typedef struct GenericPCIClass {
    PCIDeviceClass parent_class;

    void (*gen_dt_node)(DeviceState *dev);
} GenericPCIClass;

#define TYPE_GENERIC_PCI "generic_pci"
#define PCI_GEN(obj) \
    OBJECT_CHECK(PCIVPBState, (obj), TYPE_GENERIC_PCI)

#define TYPE_GENERIC_PCI_HOST "generic_pci_host"
#define PCI_GEN_HOST(obj) \
    OBJECT_CHECK(PCIDevice, (obj), TYPE_GENERIC_PCIHOST)

#define GENERIC_PCI_CLASS(klass) \
     OBJECT_CLASS_CHECK(GenericPCIClass, (klass), TYPE_GENERIC_PCI)
#define GENERIC_PCI_GET_CLASS(obj) \
    OBJECT_GET_CLASS(GenericPCIClass, (obj), TYPE_GENERIC_PCI)

#endif

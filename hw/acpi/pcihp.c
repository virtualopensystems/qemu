/*
 * QEMU<->ACPI BIOS PCI hotplug interface
 *
 * QEMU supports PCI hotplug via ACPI. This module
 * implements the interface between QEMU and the ACPI BIOS.
 * Interface specification - see docs/specs/acpi_pci_hotplug.txt
 *
 * Copyright (c) 2013, Red Hat Inc, Michael S. Tsirkin (mst@redhat.com)
 * Copyright (c) 2006 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "hw/acpi/pcihp.h"

#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/acpi/acpi.h"
#include "sysemu/sysemu.h"
#include "qemu/range.h"
#include "exec/ioport.h"
#include "exec/address-spaces.h"
#include "hw/pci/pci_bus.h"
#include "qom/qom-qobject.h"
#include "qapi/qmp/qint.h"

//#define DEBUG

#ifdef DEBUG
# define ACPI_PCIHP_DPRINTF(format, ...)     printf(format, ## __VA_ARGS__)
#else
# define ACPI_PCIHP_DPRINTF(format, ...)     do { } while (0)
#endif

#define PCI_HOTPLUG_ADDR 0xae00
#define PCI_HOTPLUG_SIZE 0x0014
#define PCI_UP_BASE 0xae00
#define PCI_DOWN_BASE 0xae04
#define PCI_EJ_BASE 0xae08
#define PCI_RMV_BASE 0xae0c
#define PCI_SEL_BASE 0xae10

typedef struct AcpiPciHpFind {
    int bsel;
    PCIBus *bus;
} AcpiPciHpFind;

static int acpi_pcihp_get_bsel(PCIBus *bus)
{
    QObject *o = object_property_get_qobject(OBJECT(bus),
                                             ACPI_PCIHP_PROP_BSEL, NULL);
    int64_t bsel = -1;
    if (o) {
        bsel = qint_get_int(qobject_to_qint(o));
    }
    if (bsel < 0) {
        return -1;
    }
    return bsel;
}

static void acpi_pcihp_test_hotplug_bus(PCIBus *bus, void *opaque)
{
    AcpiPciHpFind *find = opaque;
    if (find->bsel == acpi_pcihp_get_bsel(bus)) {
        find->bus = bus;
    }
}

static PCIBus *acpi_pcihp_find_hotplug_bus(AcpiPciHpState *s, int bsel)
{
    AcpiPciHpFind find = { .bsel = bsel, .bus = NULL };

    if (bsel < 0) {
        return NULL;
    }

    pci_for_each_bus(s->root, acpi_pcihp_test_hotplug_bus, &find);

    /* Make bsel 0 eject root bus if bsel property is not set,
     * for compatibility with non acpi setups.
     * TODO: really needed?
     */
    if (!bsel && !find.bus) {
        find.bus = s->root;
    }
    return find.bus;
}

static bool acpi_pcihp_pc_no_hotplug(AcpiPciHpState *s, PCIDevice *dev)
{
    PCIDeviceClass *pc = PCI_DEVICE_GET_CLASS(dev);
    /*
     * ACPI doesn't allow hotplug of bridge devices.  Don't allow
     * hot-unplug of bridge devices unless they were added by hotplug
     * (and so, not described by acpi).
     */
    return (pc->is_bridge && !dev->qdev.hotplugged) || pc->no_hotplug;
}

static void acpi_pcihp_eject_slot(AcpiPciHpState *s, unsigned bsel, unsigned slots)
{
    BusChild *kid, *next;
    int slot = ffs(slots) - 1;
    bool slot_free = true;
    PCIBus *bus = acpi_pcihp_find_hotplug_bus(s, bsel);

    if (!bus) {
        return;
    }

    /* Mark request as complete */
    s->acpi_pcihp_pci_status[bsel].down &= ~(1U << slot);

    QTAILQ_FOREACH_SAFE(kid, &bus->qbus.children, sibling, next) {
        DeviceState *qdev = kid->child;
        PCIDevice *dev = PCI_DEVICE(qdev);
        if (PCI_SLOT(dev->devfn) == slot) {
            if (acpi_pcihp_pc_no_hotplug(s, dev)) {
                slot_free = false;
            } else {
                object_unparent(OBJECT(qdev));
            }
        }
    }
    if (slot_free) {
        s->acpi_pcihp_pci_status[bsel].device_present &= ~(1U << slot);
    }
}

static void acpi_pcihp_update_hotplug_bus(AcpiPciHpState *s, int bsel)
{
    BusChild *kid, *next;
    PCIBus *bus = acpi_pcihp_find_hotplug_bus(s, bsel);

    /* Execute any pending removes during reset */
    while (s->acpi_pcihp_pci_status[bsel].down) {
        acpi_pcihp_eject_slot(s, bsel, s->acpi_pcihp_pci_status[bsel].down);
    }

    s->acpi_pcihp_pci_status[bsel].hotplug_enable = ~0;
    s->acpi_pcihp_pci_status[bsel].device_present = 0;

    if (!bus) {
        return;
    }
    QTAILQ_FOREACH_SAFE(kid, &bus->qbus.children, sibling, next) {
        DeviceState *qdev = kid->child;
        PCIDevice *pdev = PCI_DEVICE(qdev);
        int slot = PCI_SLOT(pdev->devfn);

        if (acpi_pcihp_pc_no_hotplug(s, pdev)) {
            s->acpi_pcihp_pci_status[bsel].hotplug_enable &= ~(1U << slot);
        }

        s->acpi_pcihp_pci_status[bsel].device_present |= (1U << slot);
    }
}

static void acpi_pcihp_update(AcpiPciHpState *s)
{
    int i;

    for (i = 0; i < ACPI_PCIHP_MAX_HOTPLUG_BUS; ++i) {
        acpi_pcihp_update_hotplug_bus(s, i);
    }
}

void acpi_pcihp_reset(AcpiPciHpState *s)
{
    acpi_pcihp_update(s);
}

static void enable_device(AcpiPciHpState *s, unsigned bsel, int slot)
{
    s->acpi_pcihp_pci_status[bsel].device_present |= (1U << slot);
}

static void disable_device(AcpiPciHpState *s, unsigned bsel, int slot)
{
    s->acpi_pcihp_pci_status[bsel].down |= (1U << slot);
}

int acpi_pcihp_device_hotplug(AcpiPciHpState *s, PCIDevice *dev,
                              PCIHotplugState state)
{
    int slot = PCI_SLOT(dev->devfn);
    int bsel = acpi_pcihp_get_bsel(dev->bus);
    if (bsel < 0) {
        return -1;
    }

    /* Don't send event when device is enabled during qemu machine creation:
     * it is present on boot, no hotplug event is necessary. We do send an
     * event when the device is disabled later. */
    if (state == PCI_COLDPLUG_ENABLED) {
        s->acpi_pcihp_pci_status[bsel].device_present |= (1U << slot);
        return 0;
    }

    if (state == PCI_HOTPLUG_ENABLED) {
        enable_device(s, bsel, slot);
    } else {
        disable_device(s, bsel, slot);
    }

    return 0;
}

static uint64_t pci_read(void *opaque, hwaddr addr, unsigned int size)
{
    AcpiPciHpState *s = opaque;
    uint32_t val = 0;
    int bsel = s->hotplug_select;

    if (bsel < 0 || bsel > ACPI_PCIHP_MAX_HOTPLUG_BUS) {
        return 0;
    }

    switch (addr) {
    case PCI_UP_BASE - PCI_HOTPLUG_ADDR:
        /* Manufacture an "up" value to cause a device check on any hotplug
         * slot with a device.  Extra device checks are harmless. */
        val = s->acpi_pcihp_pci_status[bsel].device_present &
            s->acpi_pcihp_pci_status[bsel].hotplug_enable;
        ACPI_PCIHP_DPRINTF("pci_up_read %" PRIu32 "\n", val);
        break;
    case PCI_DOWN_BASE - PCI_HOTPLUG_ADDR:
        val = s->acpi_pcihp_pci_status[bsel].down;
        ACPI_PCIHP_DPRINTF("pci_down_read %" PRIu32 "\n", val);
        break;
    case PCI_EJ_BASE - PCI_HOTPLUG_ADDR:
        /* No feature defined yet */
        ACPI_PCIHP_DPRINTF("pci_features_read %" PRIu32 "\n", val);
        break;
    case PCI_RMV_BASE - PCI_HOTPLUG_ADDR:
        val = s->acpi_pcihp_pci_status[bsel].hotplug_enable;
        ACPI_PCIHP_DPRINTF("pci_rmv_read %" PRIu32 "\n", val);
        break;
    case PCI_SEL_BASE - PCI_HOTPLUG_ADDR:
        val = s->hotplug_select;
        ACPI_PCIHP_DPRINTF("pci_sel_read %" PRIu32 "\n", val);
    default:
        break;
    }

    return val;
}

static void pci_write(void *opaque, hwaddr addr, uint64_t data,
                      unsigned int size)
{
    AcpiPciHpState *s = opaque;
    switch (addr) {
    case PCI_EJ_BASE - PCI_HOTPLUG_ADDR:
        if (s->hotplug_select >= ACPI_PCIHP_MAX_HOTPLUG_BUS) {
            break;
        }
        acpi_pcihp_eject_slot(s, s->hotplug_select, data);
        ACPI_PCIHP_DPRINTF("pciej write %" HWADDR_PRIx " <== %" PRIu64 "\n",
                      addr, data);
        break;
    case PCI_SEL_BASE - PCI_HOTPLUG_ADDR:
        s->hotplug_select = data;
        ACPI_PCIHP_DPRINTF("pcisel write %" HWADDR_PRIx " <== %" PRIu64 "\n",
                      addr, data);
    default:
        break;
    }
}

static const MemoryRegionOps acpi_pcihp_io_ops = {
    .read = pci_read,
    .write = pci_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

void acpi_pcihp_init(AcpiPciHpState *s, PCIBus *root_bus,
                     MemoryRegion *address_space_io)
{
    s->root= root_bus;
    memory_region_init_io(&s->io, NULL, &acpi_pcihp_io_ops, s,
                          "acpi-pci-hotplug",
                          PCI_HOTPLUG_SIZE);
    memory_region_add_subregion(address_space_io, PCI_HOTPLUG_ADDR, &s->io);
}

const VMStateDescription vmstate_acpi_pcihp_pci_status = {
    .name = "acpi_pcihp_pci_status",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields      = (VMStateField []) {
        VMSTATE_UINT32(up, AcpiPciHpPciStatus),
        VMSTATE_UINT32(down, AcpiPciHpPciStatus),
        VMSTATE_END_OF_LIST()
    }
};

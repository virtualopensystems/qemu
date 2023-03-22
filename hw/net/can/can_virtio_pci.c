/*
 * Virtio CAN Device
 *
 * Copyright (C) 2023 OpenSynergy GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/*
 * As templates were used (among others):
 * virtio-crypto-pci.c, virtio-gpu-pci.c, virtio-net-pci.c
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio-can.h"
#include "hw/virtio/virtio-pci.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qom/object.h"

typedef struct VirtIOCANPCI VirtIOCANPCI;

/*
 * virtio-can-pci: This extends VirtioPCIProxy.
 */
#define TYPE_VIRTIO_CAN_PCI "virtio-can-pci"
DECLARE_INSTANCE_CHECKER(VirtIOCANPCI, VIRTIO_CAN_PCI,
                         TYPE_VIRTIO_CAN_PCI)

struct VirtIOCANPCI {
    VirtIOPCIProxy parent_obj;
    VirtIOCAN vcan;

    CanBusState *canbus;
};

#if 0 /* virtio_can_pci_properties[] seems not to be mandatory */
static Property virtio_can_pci_properties[] = {
    DEFINE_PROP_UINT32("class", VirtIOPCIProxy, class_code, 0),
    DEFINE_PROP_END_OF_LIST(),
};
#endif

/*
 * Defining the often seen properties "ioeventfd" and "vectors" is to support
 * MSI-X. For now, this is regarded as an optional feature to keep it simple.
 * => No virtio_can_pci_properties[] here, virtio-rng-pci.c also has none.
 * See https://patchew.org/QEMU/20221014160947.66105-1-philmd@fungible.com/
 */

static void virtio_can_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOCANPCI *dev = VIRTIO_CAN_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vcan);

    TRACE_FUNCTION();

    virtio_can_init(&dev->vcan);

    if (virtio_can_connect_to_bus(&dev->vcan, dev->canbus) < 0) {
        error_setg(errp, "virtio_can_connect_to_bus failed");
        return;
    }

    virtio_pci_force_virtio_1(vpci_dev); /* Decisive for a "modern" device */
    if (!qdev_realize(vdev, BUS(&vpci_dev->bus), errp)) {
        virtio_can_disconnect_from_bus(&dev->vcan);
        return;
    }
}

/* See also virtio-crypto-pci.c */
static void virtio_can_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    TRACE_FUNCTION();

    /*
     * As this is a modern virtio 1.0+ only device the PCI IDs are assigned
     * automatically as in virtio_crypto_pci_class_init() with
     * vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET and device_id = 0x1040 + 0x24.
     */

    k->realize = virtio_can_pci_realize;

    /* It's DEVICE_CATEGORY_MISC also in ctucan_pci_class_init() */
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    /* device_class_set_props(dc, virtio_can_pci_properties); */

    pcidev_k->class_id = PCI_CLASS_SERIAL_CANBUS;

    dc->hotpluggable = false;
}

static void virtio_can_initfn(Object *obj)
{
    VirtIOCANPCI *dev = VIRTIO_CAN_PCI(obj);

    TRACE_FUNCTION();

    virtio_instance_init_common(obj, &dev->vcan, sizeof(dev->vcan),
                                TYPE_VIRTIO_CAN);

    object_property_add_link(obj, "canbus", TYPE_CAN_BUS,
                             (Object **)&dev->canbus,
                             qdev_prop_allow_set_link_before_realize,
                             0);
}

static const VirtioPCIDeviceTypeInfo virtio_can_pci_info = {
    .generic_name = TYPE_VIRTIO_CAN_PCI,
    .instance_size = sizeof(VirtIOCANPCI),
    .instance_init = virtio_can_initfn,
    .class_init = virtio_can_pci_class_init,
};

static void virtio_can_pci_register_types(void)
{
    virtio_pci_types_register(&virtio_can_pci_info);
}

type_init(virtio_can_pci_register_types)

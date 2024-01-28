/*
 * Vhost-user CAN virtio device PCI glue
 *
 * Copyright (c) 2024 Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/qdev-properties.h"
#include "hw/net/vhost-user-can.h"
#include "hw/virtio/virtio-pci.h"

struct VHostUserCanPCI {
    VirtIOPCIProxy parent_obj;
    VHostUserCan vdev;
};

typedef struct VHostUserCanPCI VHostUserCanPCI;

#define TYPE_VHOST_USER_CAN_PCI "vhost-user-can-pci-base"

DECLARE_INSTANCE_CHECKER(VHostUserCanPCI, VHOST_USER_CAN_PCI,
                         TYPE_VHOST_USER_CAN_PCI)

static Property vhost_user_can_pci_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void vhost_user_can_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VHostUserCanPCI *dev = VHOST_USER_CAN_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);

    vpci_dev->nvectors = 1;

    qdev_realize(vdev, BUS(&vpci_dev->bus), errp);
}

static void vhost_user_can_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);
    k->realize = vhost_user_can_pci_realize;
    set_bit(DEVICE_CATEGORY_SOUND, dc->categories);
    device_class_set_props(dc, vhost_user_can_pci_properties);
    pcidev_k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    pcidev_k->device_id = 0; /* Set by virtio-pci based on virtio id */
    pcidev_k->revision = 0x00;
    pcidev_k->class_id = PCI_CLASS_MULTIMEDIA_AUDIO;
}

static void vhost_user_can_pci_instance_init(Object *obj)
{
    VHostUserCanPCI *dev = VHOST_USER_CAN_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VHOST_USER_CAN);
}

static const VirtioPCIDeviceTypeInfo vhost_user_can_pci_info = {
    .base_name = TYPE_VHOST_USER_CAN_PCI,
    .non_transitional_name = "vhost-user-can-pci",
    .instance_size = sizeof(VHostUserCanPCI),
    .instance_init = vhost_user_can_pci_instance_init,
    .class_init = vhost_user_can_pci_class_init,
};

static void vhost_user_can_pci_register(void)
{
    virtio_pci_types_register(&vhost_user_can_pci_info);
}

type_init(vhost_user_can_pci_register);

/*
 * Vhost-user CAN virtio device
 *
 * Copyright (c) 2024 Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
 *
 * Simple wrapper of the generic vhost-user-device.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/net/vhost-user-can.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_can.h"

static const VMStateDescription vu_can_vmstate = {
    .name = "vhost-user-can",
    .unmigratable = 1,
};

static Property vcan_properties[] = {
    DEFINE_PROP_CHR("chardev", VHostUserBase, chardev),
    DEFINE_PROP_END_OF_LIST(),
};

static void vu_can_base_realize(DeviceState *dev, Error **errp)
{
    VHostUserBase *vub = VHOST_USER_BASE(dev);
    VHostUserBaseClass *vubs = VHOST_USER_BASE_GET_CLASS(dev);

    vub->virtio_id = VIRTIO_ID_CAN;
    vub->num_vqs = 3;
    vub->config_size = sizeof(struct virtio_can_config);

    vubs->parent_realize(dev, errp);
}

static void vu_can_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VHostUserBaseClass *vubc = VHOST_USER_BASE_CLASS(klass);

    dc->vmsd = &vu_can_vmstate;
    device_class_set_props(dc, vcan_properties);
    device_class_set_parent_realize(dc, vu_can_base_realize,
                                    &vubc->parent_realize);

    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}

static const TypeInfo vu_can_info = {
    .name = TYPE_VHOST_USER_CAN,
    .parent = TYPE_VHOST_USER_BASE,
    .instance_size = sizeof(VHostUserCan),
    .class_init = vu_can_class_init,
};

static void vu_can_register_types(void)
{
    type_register_static(&vu_can_info);
}

type_init(vu_can_register_types)

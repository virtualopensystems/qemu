/*
 * Vhost-user Can virtio device
 *
 * Copyright (c) 2024 Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_VHOST_USER_CAN_H
#define QEMU_VHOST_USER_CAN_H

#include "hw/virtio/virtio.h"
#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-user.h"
#include "hw/virtio/vhost-user-device.h"

#define TYPE_VHOST_USER_CAN "vhost-user-can"
OBJECT_DECLARE_SIMPLE_TYPE(VHostUserCan, VHOST_USER_CAN)

struct VHostUserCan {
    /*< private >*/
    VHostUserBase parent;
    /*< public >*/
};

#endif /* QEMU_VHOST_USER_CAN_H */

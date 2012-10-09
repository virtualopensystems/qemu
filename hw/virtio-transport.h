/*
 * Virtio transport header
 *
 * Copyright (c) 2011 - 2012 Samsung Electronics Co., Ltd.
 *
 * Author:
 *  Evgeny Voevodin <e.voevodin@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef VIRTIO_TRANSPORT_H_
#define VIRTIO_TRANSPORT_H_

#include "qdev.h"
#include "qemu-common.h"

#define VIRTIO_MMIO "virtio-mmio"
#define VIRTIO_PCI "virtio-pci"

#define TYPE_VIRTIO_BUS "virtio-bus"
#define VIRTIO_BUS(obj) OBJECT_CHECK(virtio_bus, (obj), TYPE_VIRTIO_BUS)

struct VirtIOTransportLink;

typedef int (*virtio_backend_init_cb)(DeviceState *dev, VirtIODevice *vdev,
             struct VirtIOTransportLink *trl);

typedef struct VirtIOTransportLink {
    DeviceState *tr;
    virtio_backend_init_cb cb;
    uint32_t host_features;
    QTAILQ_ENTRY(VirtIOTransportLink) sibling;
} VirtIOTransportLink;

/*
 * Find transport device by its ID.
 */
VirtIOTransportLink* virtio_find_transport(const char *name);

/*
 * Count transport devices by ID.
 */
uint32_t virtio_count_transports(const char *name);

/*
 * Initialize new transport device
 */
char* virtio_init_transport(DeviceState *dev, VirtIOTransportLink **trl,
        const char* name, virtio_backend_init_cb cb);

/*
 * Unplug back-end from system bus and plug it into transport bus.
 */
void virtio_plug_into_transport(DeviceState *dev, VirtIOTransportLink *trl);

/*
 * Execute call-back on back-end initialization.
 * Performs initialization of MMIO or PCI transport.
 */
int virtio_call_backend_init_cb(DeviceState *dev, VirtIOTransportLink *trl,
        VirtIODevice *vdev);

#endif /* VIRTIO_TRANSPORT_H_ */

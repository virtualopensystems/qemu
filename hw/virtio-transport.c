/*
 * Virtio transport bindings
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

#include "virtio-transport.h"

#define VIRTIO_TRANSPORT_BUS "virtio-transport"

static QTAILQ_HEAD(, VirtIOTransportLink) transport_links =
        QTAILQ_HEAD_INITIALIZER(transport_links);

/*
 * Find transport device by its ID.
 */
VirtIOTransportLink* virtio_find_transport(const char *name)
{
    VirtIOTransportLink *trl;

    assert(name != NULL);

    QTAILQ_FOREACH(trl, &transport_links, sibling) {
        if (trl->tr->id != NULL) {
            if (!strcmp(name, trl->tr->id)) {
                return trl;
            }
        }
    }

    return NULL;
}

/*
 * Count transport devices by ID.
 */
uint32_t virtio_count_transports(const char *name)
{
    VirtIOTransportLink *trl;
    uint32_t i = 0;

    QTAILQ_FOREACH(trl, &transport_links, sibling) {
        if (name == NULL) {
            i++;
            continue;
        }

        if (trl->tr->id != NULL) {
            if (!strncmp(name, trl->tr->id,strlen(name))) {
                i++;
            }
        }
    }
    return i;
}

/*
 * Initialize new transport device
 */
char* virtio_init_transport(DeviceState *dev, VirtIOTransportLink **trl,
        const char* name, virtio_backend_init_cb cb)
{
    VirtIOTransportLink *link = g_malloc0(sizeof(VirtIOTransportLink));
    char *buf;
    size_t len;
    uint32_t i;

    assert(dev != NULL);
    assert(name != NULL);
    assert(trl != NULL);

    i = virtio_count_transports(name);
    len = strlen(name) + 16;
    buf = g_malloc(len);
    snprintf(buf, len, "%s.%d", name, i);
    qbus_create(TYPE_VIRTIO_BUS, dev, buf);

    /* Add new transport */
    QTAILQ_INSERT_TAIL(&transport_links, link, sibling);
    link->tr = dev;
    link->cb = cb;
    // TODO: Add a link property
    *trl = link;
    return buf;
}

/*
 * Unplug back-end from system bus and plug it into transport bus.
 */
void virtio_plug_into_transport(DeviceState *dev, VirtIOTransportLink *trl)
{
    BusChild *kid;

    /* Unplug back-end from system bus */
    QTAILQ_FOREACH(kid, &qdev_get_parent_bus(dev)->children, sibling) {
        if (kid->child == dev) {
            QTAILQ_REMOVE(&qdev_get_parent_bus(dev)->children, kid, sibling);
            break;
        }
    }

    /* Plug back-end into transport's bus */
    qdev_set_parent_bus(dev, QLIST_FIRST(&trl->tr->child_bus));

}

/*
 * Execute call-back on back-end initialization.
 * Performs initialization of MMIO or PCI transport.
 */
int virtio_call_backend_init_cb(DeviceState *dev, VirtIOTransportLink *trl,
        VirtIODevice *vdev)
{
    if (trl->cb) {
        return trl->cb(dev, vdev, trl);
    }

    return 0;
}

static const TypeInfo virtio_bus_info = {
    .name = TYPE_VIRTIO_BUS,
    .parent = TYPE_BUS,
    .instance_size = sizeof(BusState),
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_bus_info);
}

type_init(virtio_register_types)

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

#ifndef QEMU_VIRTIO_CAN_H
#define QEMU_VIRTIO_CAN_H

#include "hw/virtio/virtio.h"
#include "standard-headers/linux/virtio_can.h"
/* #include "qemu/error-report.h" */
#include "qemu/log.h"
#include "qom/object.h"
#include "net/can_emu.h"

#define TYPE_VIRTIO_CAN "virtio-can-device"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOCAN, VIRTIO_CAN)
#define VIRTIO_CAN_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_CAN)

/* Debug stuff */
#define pr_err(fmt, ...) qemu_log("E: [virtio_can]: " fmt , ## __VA_ARGS__)
#define pr_warn(fmt, ...) qemu_log("W: [virtio_can]: " fmt , ## __VA_ARGS__)
#define pr_info(fmt, ...) qemu_log("I: [virtio_can]: " fmt , ## __VA_ARGS__)

#ifdef DEBUG_CAN
#define pr_debug(fmt, ...) \
    qemu_log("D: [virtio_can]: " fmt , ## __VA_ARGS__)
#else
#define pr_debug(fmt, ...) \
    do { \
    } while (0)
#endif

#define TRACE_ENTER() pr_debug("Enter %s()\n", __func__)
#define TRACE_LEAVE() pr_debug("Leave %s()\n", __func__)
#define TRACE_FUNCTION() pr_debug("%s()\n", __func__)

/* CAN device queues */
#define DEVICE_QUEUE_TX 0u /* Driver side view! The device receives here */
#define DEVICE_QUEUE_RX 1u /* Driver side view! The device transmits here */
#define DEVICE_QUEUE_CTRL 2u
#define DEVICE_QUEUE_CNT 3u

/* CAN controller states */
#define CAN_CS_UNINIT 0x00
#define CAN_CS_STARTED 0x01
#define CAN_CS_STOPPED 0x02

struct VirtIOCAN {
    VirtIODevice parent_obj;

    VirtQueue *vq[DEVICE_QUEUE_CNT];

    /* Count of messages from QEMU bus dropped */
    uint64_t rx_from_bus_dropped;
    /* Count of messages from QEMU bus received and forwarded to Virtio */
    uint64_t rx_from_bus_to_driver;
    /* Count of transmitted messages */
    uint64_t tx_from_driver_to_bus;

    uint8_t ctrl_state;

    CanBusClientState bus_client;

    bool busoff;

    /* Support classic CAN */
    bool support_can_classic;
    /* Support CAN FD */
    bool support_can_fd;
};

int virtio_can_connect_to_bus(VirtIOCAN *can, CanBusState *bus);
void virtio_can_disconnect_from_bus(VirtIOCAN *can);

void virtio_can_init(VirtIOCAN *vcan);

#endif

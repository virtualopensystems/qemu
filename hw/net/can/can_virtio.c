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

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/iov.h"
#include "standard-headers/linux/virtio_can.h"
#include "hw/virtio/virtio-can.h"
#include "hw/virtio/virtio.h"

/* See also virtio_net_started() */
static bool virtio_can_started(VirtIOCAN *vcan)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(vcan);

    return (vdev->status & VIRTIO_CONFIG_S_DRIVER_OK) &&
            vcan->ctrl_state == CAN_CS_STARTED && vdev->vm_running;
}

/*
 * Controller stop and controller start has only a local impact on the device.
 * If the state is stopped, everything received from the internal qemu CAN bus
 * is dropped as the controller is inactive. If the state is started, messages
 * are forwarded in both directions.
 */
static void virtio_can_controller_stop(VirtIOCAN *vcan)
{
    vcan->ctrl_state = CAN_CS_STOPPED;
}

static void virtio_can_controller_start(VirtIOCAN *vcan)
{
    vcan->ctrl_state = CAN_CS_STARTED;
}

static void virtio_can_set_status(VirtIODevice *vdev, uint8_t status)
{
    VirtIOCAN *can = VIRTIO_CAN(vdev);

    /* TRACE_FUNCTION(); */

    if (!vdev->vm_running) {
        return;
    }

    if (vdev->status != status) {
        pr_debug("%s: Status old = 0x%" PRIX32 ", status new = 0x%" PRIX32 "\n",
                 __func__, vdev->status, status);
    }

    vdev->status = status;

    if ((status & VIRTIO_CONFIG_S_DRIVER_OK) == 0) {
        virtio_can_controller_stop(can);
    }
}

/*
 * Process DEVICE_QUEUE_TX. Driver side view! The device receives here
 * so we forward messages received from virtio CAN to the qemu CAN bus
 */
static void virtio_can_tx_cb(VirtIODevice *vdev, VirtQueue *vqueue)
{
    VirtIOCAN *vcan = VIRTIO_CAN(vdev);
    VirtQueueElement *element;
    size_t req_size;
    size_t resp_size;
    struct virtio_can_tx_out request;
    struct virtio_can_tx_in response;
    qemu_can_frame qemu_frame;
    uint32_t flags;
    uint16_t msg_type;
    uint16_t sdu_len;

    /* TRACE_FUNCTION(); */

    for (;;) {
        element = virtqueue_pop(vqueue, sizeof(VirtQueueElement));
        if (element == NULL) {
            break;
        }

        /* Device => Driver part */
        resp_size = iov_size(element->in_sg, element->in_num);
        if (resp_size < sizeof(response.result)) {
            virtio_error(vdev, "Wrong response size (%zu bytes)\n", resp_size);
            goto on_failure_no_result;
        }

        response.result = VIRTIO_CAN_RESULT_NOT_OK;

        /* Driver => Device part */
        req_size = iov_size(element->out_sg, element->out_num);
        if (req_size < offsetof(struct virtio_can_tx_out, sdu)) {
            virtio_error(vdev, "TX: Message too small for header\n");
            goto on_failure;
        }

        if (req_size > sizeof(struct virtio_can_tx_out)) {
            req_size = sizeof(struct virtio_can_tx_out);
        }

        iov_to_buf(element->out_sg, element->out_num, 0, &request, req_size);

        msg_type = le16_to_cpu(request.msg_type);
        if (msg_type != VIRTIO_CAN_TX) {
            virtio_error(vdev, "TX: Message type 0x%x unknown\n", msg_type);
            goto on_failure_no_result;
        }

        flags = le32_to_cpu(request.flags);
        sdu_len = le16_to_cpu(request.length);
        if (flags & VIRTIO_CAN_FLAGS_FD) {
            if (sdu_len > 64) {
                pr_warn("%s(): Cut sdu_len from %u to 64\n", __func__, sdu_len);
                sdu_len = 64;
            }
        } else {
            if (sdu_len > 8) {
                pr_warn("%s(): Cut sdu_len from %u to 8\n", __func__, sdu_len);
                sdu_len = 8;
            }
        }
        if (req_size < offsetof(struct virtio_can_tx_out, sdu) + sdu_len) {
            virtio_error(vdev, "TX: Message too small for payload\n");
            goto on_failure;
        }

        if (!virtio_can_started(vcan)) {
            goto on_failure;
        }

        /* 
         * Copy Virtio frame structure to qemu frame structure and
         * check while doing this whether the frame type was negotiated
         */
        qemu_frame.can_id = le32_to_cpu(request.can_id);
        if (flags & VIRTIO_CAN_FLAGS_EXTENDED) {
            qemu_frame.can_id &= QEMU_CAN_EFF_MASK;
            qemu_frame.can_id |= QEMU_CAN_EFF_FLAG;
        } else {
            qemu_frame.can_id &= QEMU_CAN_SFF_MASK;
        }

        if (flags & VIRTIO_CAN_FLAGS_RTR) {
            if (!virtio_vdev_has_feature(vdev, VIRTIO_CAN_F_CAN_CLASSIC) ||
                !virtio_vdev_has_feature(vdev, VIRTIO_CAN_F_RTR_FRAMES)) {
                virtio_error(vdev, "TX: RTR frames not negotiated\n");
                goto on_failure;
            }
            qemu_frame.can_id |= QEMU_CAN_RTR_FLAG;
        }

        if (flags & VIRTIO_CAN_FLAGS_FD) {
            if (!virtio_vdev_has_feature(vdev, VIRTIO_CAN_F_CAN_FD)) {
                virtio_error(vdev, "TX: FD frames not negotiated\n");
                goto on_failure;
            }
            qemu_frame.flags |= QEMU_CAN_FRMF_TYPE_FD;
        } else {
            if (!virtio_vdev_has_feature(vdev, VIRTIO_CAN_F_CAN_CLASSIC)) {
                virtio_error(vdev, "TX: Classic frames not negotiated\n");
                goto on_failure;
            }
            qemu_frame.flags = 0;
        }

        qemu_frame.can_dlc = (uint8_t)sdu_len;
        memcpy(qemu_frame.data, request.sdu, sdu_len);

        can_bus_client_send(&vcan->bus_client, &qemu_frame, 1);

        vcan->tx_from_driver_to_bus++;

        response.result = VIRTIO_CAN_RESULT_OK;

on_failure:
        iov_from_buf(element->in_sg, element->in_num, 0, &response,
                     sizeof(response.result));

on_failure_no_result:
        virtqueue_push(vqueue, element, resp_size);
    }

    virtio_notify(vdev, vqueue);
}

static bool virtio_can_can_receive(CanBusClientState *client)
{
    VirtIOCAN *vcan = container_of(client, VirtIOCAN, bus_client);

    /* TRACE_FUNCTION(); */

    return virtio_can_started(vcan);
}

/* From qemu internal bus => virtio */
static ssize_t virtio_can_receive(CanBusClientState *client,
                                  const qemu_can_frame *frames,
                                  size_t frames_cnt)
{
    VirtIOCAN *vcan = container_of(client, VirtIOCAN, bus_client);
    VirtIODevice *vdev = &vcan->parent_obj;
    VirtQueue *vqueue = vcan->vq[DEVICE_QUEUE_RX];
    const qemu_can_frame *frame = frames;
    VirtQueueElement *element;
    struct virtio_can_rx can_rx;
    uint32_t flags;
    uint16_t sdu_len;
    uint16_t msg_len;

    /* TRACE_FUNCTION(); */

    /*
     * Thought initially that frames_cnt may be used to process more than only
     * a single frame but nobody uses the parameter in this way
     */
    if (frames_cnt <= 0) {
        return 0;
    }

    if (!virtio_can_started(vcan)) {
        assert(frames_cnt <= SSIZE_MAX);
        return (ssize_t)frames_cnt;
    }

    if (frame->can_id & QEMU_CAN_ERR_FLAG) {
        if (frame->can_id & QEMU_CAN_ERR_BUSOFF) {
            pr_warn("Got BusOff error frame, device does a local bus off\n");
            vcan->busoff = true;
            virtio_can_controller_stop(vcan);
            virtio_notify_config(vdev);
        } else {
            pr_info("Dropping error frame 0x%" PRIX32 "\n", frame->can_id);
        }
        return 1;
    }

    if (frame->flags & QEMU_CAN_FRMF_TYPE_FD) {
        if (!virtio_vdev_has_feature(vdev, VIRTIO_CAN_F_CAN_FD)) {
            return 1; /* Drop non-supported CAN FD frame */
        }
    } else {
        if (!virtio_vdev_has_feature(vdev, VIRTIO_CAN_F_CAN_CLASSIC)) {
            return 1; /* Drop non-supported CAN classic frame */
        }
    }

    if ((frame->can_id & QEMU_CAN_RTR_FLAG) &&
        !virtio_vdev_has_feature(vdev, VIRTIO_CAN_F_RTR_FRAMES)) {
        return 1; /* Drop non-supported RTR frame */
    }

    element = virtqueue_pop(vqueue, sizeof(VirtQueueElement));
    if (element == NULL) {
        vcan->rx_from_bus_dropped++;
        return 1;
    }

    can_rx.msg_type = cpu_to_le16(VIRTIO_CAN_RX);
    sdu_len = frame->can_dlc;
    can_rx.length = cpu_to_le16(sdu_len);
    can_rx.reserved = cpu_to_le32(0);
    if (frame->can_id & QEMU_CAN_EFF_FLAG) {
        flags = VIRTIO_CAN_FLAGS_EXTENDED;
        can_rx.can_id = cpu_to_le32(frame->can_id & QEMU_CAN_EFF_MASK);
    } else {
        flags = 0;
        can_rx.can_id = cpu_to_le32(frame->can_id & QEMU_CAN_SFF_MASK);
    }
    if (frame->can_id & QEMU_CAN_RTR_FLAG) {
        flags |= VIRTIO_CAN_FLAGS_RTR;
    }
    if (frame->flags & QEMU_CAN_FRMF_TYPE_FD) {
        flags |= VIRTIO_CAN_FLAGS_FD;
        if (sdu_len > 64) {
            pr_warn("%s(): Cut length from %u to 64\n", __func__, sdu_len);
            sdu_len = 64;
        }
    } else {
        if (sdu_len > 8) {
            pr_warn("%s(): Cut length from %u to 8\n", __func__, sdu_len);
            sdu_len = 8;
        }
    }
    can_rx.flags = cpu_to_le32(flags);
    memcpy(can_rx.sdu, frame->data, sdu_len);

    msg_len = offsetof(struct virtio_can_rx, sdu) + can_rx.length;
    iov_from_buf(element->in_sg, element->in_num, 0, &can_rx, msg_len);
    virtqueue_push(vqueue, element, msg_len);

    vcan->rx_from_bus_to_driver++;

    virtio_notify(vdev, vqueue);

    return 1;
}

static CanBusClientInfo virtio_can_bus_client_info = {
    .can_receive = virtio_can_can_receive,
    .receive = virtio_can_receive,
};

/* Compare with ctucan_connect_to_bus() */
int virtio_can_connect_to_bus(VirtIOCAN *vcan, CanBusState *bus)
{
    TRACE_FUNCTION();

    vcan->bus_client.info = &virtio_can_bus_client_info;

    if (bus == NULL) {
        return -EINVAL;
    }

    if (can_bus_insert_client(bus, &vcan->bus_client) < 0) {
        return -1;
    }

    return 0;
}

/* Compare with ctucan_disconnect() */
void virtio_can_disconnect_from_bus(VirtIOCAN *vcan)
{
    TRACE_FUNCTION();

    can_bus_remove_client(&vcan->bus_client);
}

void virtio_can_init(VirtIOCAN *vcan)
{
    TRACE_FUNCTION();

    (void)vcan;
}

/* Control message received */
static void virtio_can_ctrl_cb(VirtIODevice *vdev, VirtQueue *vqueue)
{
    VirtIOCAN *vcan = VIRTIO_CAN(vdev);
    size_t req_size;
    size_t resp_size;
    uint16_t msg_type;

    /* TRACE_FUNCTION(); */

    for (;;) {
        VirtQueueElement *element;
        struct virtio_can_control_out request;
        struct virtio_can_control_in response;

        element = virtqueue_pop(vqueue, sizeof(VirtQueueElement));
        if (element == NULL) {
            break;
        }

        /* Device => Driver part */
        resp_size = iov_size(element->in_sg, element->in_num);
        if (resp_size < sizeof(response.result)) {
            virtio_error(vdev, "Wrong response size (%zu bytes)\n", resp_size);
            goto on_failure_no_result;
        }

        response.result = VIRTIO_CAN_RESULT_NOT_OK;

        /* Driver => Device part */
        req_size = iov_size(element->out_sg, element->out_num);
        if (req_size < sizeof(struct virtio_can_control_out)) {
            virtio_error(vdev, "Wrong request size (%zu bytes)\n", req_size);
            goto on_failure;
        }

        iov_to_buf(element->out_sg, element->out_num, 0, &request,
                   sizeof(struct virtio_can_control_out));

        msg_type = le16_to_cpu(request.msg_type);
        switch (msg_type) {
        case VIRTIO_CAN_SET_CTRL_MODE_START:
            pr_debug("Received VIRTIO_CAN_SET_CTRL_MODE_START\n");
            vcan->busoff = false;
            virtio_can_controller_start(vcan);
            response.result = VIRTIO_CAN_RESULT_OK;
            break;
        case VIRTIO_CAN_SET_CTRL_MODE_STOP:
            pr_debug("Received VIRTIO_CAN_SET_CTRL_MODE_STOP\n");
            virtio_can_controller_stop(vcan);
            vcan->busoff = false;
            pr_info("RX frames from qemu internal bus to driver: %" PRIu64 "\n",
                    vcan->rx_from_bus_to_driver);
            pr_info("RX frames from qemu internal bus dropped: %" PRIu64 "\n",
                    vcan->rx_from_bus_dropped);
            pr_info("TX frames from driver to qemu internal bus: %" PRIu64 "\n",
                    vcan->tx_from_driver_to_bus);
            vcan->rx_from_bus_to_driver = 0;
            vcan->rx_from_bus_dropped = 0;
            vcan->tx_from_driver_to_bus = 0;
            response.result = VIRTIO_CAN_RESULT_OK;
            break;
        default:
            virtio_error(vdev, "Ctrl queue: msg type 0x%" PRIX16 " unknown\n",
                         msg_type);
            break;
        }

        response.result = VIRTIO_CAN_RESULT_OK;

on_failure:
        iov_from_buf(element->in_sg, element->in_num, 0, &response,
                     sizeof(response.result));

on_failure_no_result:
        virtqueue_push(vqueue, element, resp_size);
    }

    virtio_notify(vdev, vqueue);
}

static void virtio_can_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOCAN *vcan = VIRTIO_CAN(dev);

    TRACE_FUNCTION();

    (void)errp;

    virtio_init(vdev, VIRTIO_ID_CAN,
                sizeof(struct virtio_can_config));
    vcan->vq[DEVICE_QUEUE_TX] = virtio_add_queue(vdev, 64, virtio_can_tx_cb);
    vcan->vq[DEVICE_QUEUE_RX] = virtio_add_queue(vdev, 64, NULL);
    vcan->vq[DEVICE_QUEUE_CTRL] = virtio_add_queue(vdev, 4, virtio_can_ctrl_cb);
}

static void virtio_can_device_unrealize(DeviceState *dev)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOCAN *vcan = VIRTIO_CAN(dev);
    unsigned int qi;

    TRACE_FUNCTION();

    for (qi = 0; qi < DEVICE_QUEUE_CNT; qi++) {
        virtio_delete_queue(vcan->vq[qi]);
    }

    virtio_cleanup(vdev);
}

/* Device offered features */
static uint64_t virtio_can_get_features(VirtIODevice *vdev, uint64_t features,
                                        Error **errp)
{
    VirtIOCAN *vcan = VIRTIO_CAN(vdev);

    (void)errp;

    pr_debug("%s: Features in = 0x%" PRIX64 "\n", __func__, features);

    virtio_add_feature(&features, VIRTIO_F_VERSION_1);

    if (vcan->support_can_classic) {
        virtio_add_feature(&features, VIRTIO_CAN_F_CAN_CLASSIC);
        virtio_add_feature(&features, VIRTIO_CAN_F_RTR_FRAMES);
    }
    if (vcan->support_can_fd) {
        virtio_add_feature(&features, VIRTIO_CAN_F_CAN_FD);
    }

    /*
     * The feature VIRTIO_CAN_F_LATE_TX_ACK is not supported by the device.
     * To support this, needed
     *   - a more direct interface to SocketCAN
     *   - SocketCAN reliably looping back own send messages (problem here)
     *   - implementation effort
     *
     * Next question is whether the feature flag VIRTIO_CAN_F_LATE_TX_ACK
     * should not be removed totally just leaving a sentence in the spec that
     * a sent message SHOULD be marked as used after it has been sent on the CAN
     * bus but that due to implementation restrictions in the used environment
     * a sent message MAY already be marked as used immediately after having
     * been scheduled for transmission. Upcoming experience shows anyway that
     * the presence or absence of the feature flag has no impact on the driver
     * at all but is for informational purposes only to learn what the device
     * supports here.
     */

    pr_debug("%s: Features out = 0x%" PRIX64 "\n", __func__, features);

    return features;
}

static void virtio_can_get_config(VirtIODevice *vdev, uint8_t *data)
{
    struct virtio_can_config *config = (struct virtio_can_config *)data;
    VirtIOCAN *vcan = VIRTIO_CAN(vdev);

    TRACE_FUNCTION();

    if (vcan->busoff) {
        config->status = cpu_to_le32(VIRTIO_CAN_S_CTRL_BUSOFF);
    } else {
        config->status = cpu_to_le32(0);
    }
}

static Property virtio_can_properties[] = {
    DEFINE_PROP_BOOL("classic", VirtIOCAN, support_can_classic, true),
    DEFINE_PROP_BOOL("fd", VirtIOCAN, support_can_fd, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_can_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    TRACE_FUNCTION();

    device_class_set_props(dc, virtio_can_properties);
    // Save and restore QEMU state not supported at least for now
    /* dc->vmsd = &vmstate_virtio_can; */
    /* Other CAN devices also set DEVICE_CATEGORY_MISC,
     * none sets DEVICE_CATEGORY_NETWORK */
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    /* Sound sets realize, unrealize, get_features, get_config and set_status
     * Network sets more. Really documented is nothing, lack of comments */
    vdc->realize = virtio_can_device_realize;
    vdc->unrealize = virtio_can_device_unrealize;
    vdc->get_features = virtio_can_get_features;
    vdc->get_config = virtio_can_get_config;
    vdc->set_config = NULL; /* No driver writable fields in config space */
    vdc->set_status = virtio_can_set_status;
}

/*
 * See virtio-rng.c, virtio-net.c and also
 * https://sebastienbourdelin.com/2021/06/16/writing-a-custom-device-for-qemu/
 */
static const TypeInfo virtio_can_info = {
    .name = TYPE_VIRTIO_CAN,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOCAN),
    .class_init = virtio_can_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_can_info);
}

type_init(virtio_register_types)

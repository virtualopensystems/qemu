/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2021-2023 OpenSynergy GmbH
 */
#ifndef _LINUX_VIRTIO_VIRTIO_CAN_H
#define _LINUX_VIRTIO_VIRTIO_CAN_H

#include "standard-headers/linux/types.h"
#include "standard-headers/linux/virtio_types.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_config.h"

/* Feature bit numbers */
#define VIRTIO_CAN_F_CAN_CLASSIC        0
#define VIRTIO_CAN_F_CAN_FD             1
#define VIRTIO_CAN_F_LATE_TX_ACK        2
#define VIRTIO_CAN_F_RTR_FRAMES         3

/* CAN Result Types */
#define VIRTIO_CAN_RESULT_OK            0
#define VIRTIO_CAN_RESULT_NOT_OK        1

/* CAN flags to determine type of CAN Id */
#define VIRTIO_CAN_FLAGS_EXTENDED       0x8000
#define VIRTIO_CAN_FLAGS_FD             0x4000
#define VIRTIO_CAN_FLAGS_RTR            0x2000

struct virtio_can_config {
#define VIRTIO_CAN_S_CTRL_BUSOFF (1u << 0) /* Controller BusOff */
	/* CAN controller status */
	__le16 status;
};

/* TX queue message types */
struct virtio_can_tx_out {
#define VIRTIO_CAN_TX                   0x0001
	__le16 msg_type;
	__le16 length; /* 0..8 CC, 0..64 CAN­FD, 0..2048 CAN­XL, 12 bits */
	__le32 reserved; /* May be needed in part for CAN XL priority */
	__le32 flags;
	__le32 can_id;
	__u8 sdu[64];
};

struct virtio_can_tx_in {
	__u8 result;
};

/* RX queue message types */
struct virtio_can_rx {
#define VIRTIO_CAN_RX                   0x0101
	__le16 msg_type;
	__le16 length; /* 0..8 CC, 0..64 CAN­FD, 0..2048 CAN­XL, 12 bits */
	__le32 reserved; /* May be needed in part for CAN XL priority */
	__le32 flags;
	__le32 can_id;
	__u8 sdu[64];
};

/* Control queue message types */
struct virtio_can_control_out {
#define VIRTIO_CAN_SET_CTRL_MODE_START  0x0201
#define VIRTIO_CAN_SET_CTRL_MODE_STOP   0x0202
	__le16 msg_type;
};

struct virtio_can_control_in {
	__u8 result;
};

#endif /* #ifndef _LINUX_VIRTIO_VIRTIO_CAN_H */

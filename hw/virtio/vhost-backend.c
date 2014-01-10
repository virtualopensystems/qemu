/*
 * vhost-backend
 *
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-backend.h"
#include "qemu/error-report.h"
#include "qemu/sockets.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/vhost.h>

#define VHOST_MEMORY_MAX_NREGIONS    8
#define VHOST_USER_SOCKTO            (300) /* msec */

typedef enum VhostUserRequest {
    VHOST_USER_NONE = 0,
    VHOST_USER_GET_FEATURES = 1,
    VHOST_USER_SET_FEATURES = 2,
    VHOST_USER_SET_OWNER = 3,
    VHOST_USER_RESET_OWNER = 4,
    VHOST_USER_SET_MEM_TABLE = 5,
    VHOST_USER_SET_LOG_BASE = 6,
    VHOST_USER_SET_LOG_FD = 7,
    VHOST_USER_SET_VRING_NUM = 8,
    VHOST_USER_SET_VRING_ADDR = 9,
    VHOST_USER_SET_VRING_BASE = 10,
    VHOST_USER_GET_VRING_BASE = 11,
    VHOST_USER_SET_VRING_KICK = 12,
    VHOST_USER_SET_VRING_CALL = 13,
    VHOST_USER_SET_VRING_ERR = 14,
    VHOST_USER_NET_SET_BACKEND = 15,
    VHOST_USER_ECHO = 16,
    VHOST_USER_MAX
} VhostUserRequest;

typedef struct VhostUserMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
} VhostUserMemoryRegion;

typedef struct VhostUserMemory {
    uint32_t nregions;
    uint32_t padding;
    VhostUserMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostUserMemory;

typedef struct VhostUserMsg {
    VhostUserRequest request;

#define VHOST_USER_VERSION_MASK     (0x3)
#define VHOST_USER_REPLY_MASK       (0x1<<2)
    uint32_t flags;
    uint32_t size; /* the following payload size */
    union {
        uint64_t u64;
        struct vhost_vring_state state;
        struct vhost_vring_addr addr;
        VhostUserMemory memory;
    };
} QEMU_PACKED VhostUserMsg;

static VhostUserMsg m __attribute__ ((unused));
#define VHOST_USER_HDR_SIZE (sizeof(m.request) \
                            + sizeof(m.flags) \
                            + sizeof(m.size))

#define VHOST_USER_PAYLOAD_SIZE (sizeof(m) - VHOST_USER_HDR_SIZE)

/* The version of the protocol we support */
#define VHOST_USER_VERSION    (0x1)

static int vhost_user_recv(int fd, VhostUserMsg *msg)
{
    ssize_t r;
    uint8_t *p = (uint8_t *) msg;

    /* read the header */
    do {
        r = read(fd, p, VHOST_USER_HDR_SIZE);
    } while (r < 0 && errno == EINTR);

    if (r < 0) {
        error_report("Failed to read msg header, reason: %s\n",
                     strerror(errno));
        goto fail;
    }

    if (r != VHOST_USER_HDR_SIZE) {
        error_report("Failed to read msg header. Read %zu instead of %zu.\n",
                     r, VHOST_USER_HDR_SIZE);
        goto fail;
    }

    /* validate received flags */
    if (msg->flags != (VHOST_USER_REPLY_MASK | VHOST_USER_VERSION)) {
        error_report("Failed to read msg header."
                     " Flags 0x%x instead of 0x%x.\n",
                     msg->flags, VHOST_USER_REPLY_MASK | VHOST_USER_VERSION);
        goto fail;
    }

    /* validate message size is sane */
    if (msg->size > VHOST_USER_PAYLOAD_SIZE) {
        error_report("Failed to read msg header."
                     " Size %d exceeds the maximum %zu.\n",
                     msg->size, VHOST_USER_PAYLOAD_SIZE);
        goto fail;
    }

    p += VHOST_USER_HDR_SIZE;

    /* read the payload */
    do {
        r = read(fd, p, msg->size);
    } while (r < 0 && errno == EINTR);

    if (r < 0) {
        error_report("Failed to read msg payload, reason: %s\n",
                     strerror(errno));
        goto fail;
    }

    if (r != msg->size) {
        error_report("Failed to read msg payload. Read %zu instead of %d.\n",
                     r, msg->size);
        goto fail;
    }

    return 0;

fail:
    return -1;
}

static int vhost_user_send_fds(int fd, VhostUserMsg *msg, int *fds,
        size_t fd_num)
{
    int r;

    struct msghdr msgh;
    struct iovec iov;

    size_t fd_size = fd_num * sizeof(int);
    char control[CMSG_SPACE(fd_size)];
    struct cmsghdr *cmsg;

    memset(&msgh, 0, sizeof(msgh));
    memset(control, 0, sizeof(control));

    /* set the payload */
    iov.iov_base = msg;
    iov.iov_len = VHOST_USER_HDR_SIZE + msg->size;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    if (fd_num) {
        msgh.msg_control = control;
        msgh.msg_controllen = sizeof(control);

        cmsg = CMSG_FIRSTHDR(&msgh);

        cmsg->cmsg_len = CMSG_LEN(fd_size);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsg), fds, fd_size);
    } else {
        msgh.msg_control = 0;
        msgh.msg_controllen = 0;
    }

    do {
        r = sendmsg(fd, &msgh, 0);
    } while (r < 0 && errno == EINTR);

    if (r < 0) {
        error_report("Failed to send msg(%d), reason: %s\n",
                msg->request, strerror(errno));
        goto fail;
    }

    if (r != VHOST_USER_HDR_SIZE + msg->size) {
        error_report("Failed to send msg(%d). Sent %d instead of %zu.\n",
                msg->request, r, VHOST_USER_HDR_SIZE + msg->size);
        goto fail;
    }

    return 0;

fail:
    return -1;
}

static int vhost_user_echo(struct vhost_dev *dev)
{
    VhostUserMsg msg;
    int fd = dev->control;

    if (fd < 0) {
        return 0;
    }

    /* check connection */
    msg.request = VHOST_USER_ECHO;
    msg.flags = VHOST_USER_VERSION;
    msg.size = 0;

    if (vhost_user_send_fds(fd, &msg, 0, 0) < 0) {
        error_report("ECHO failed\n");
        return -1;
    }

    if (vhost_user_recv(fd, &msg) < 0) {
        error_report("ECHO failed\n");
        return -1;
    }

    return 0;
}

static int vhost_user_call(struct vhost_dev *dev, unsigned long int request,
        void *arg)
{
    int fd = dev->control;
    VhostUserMsg msg;
    int result = 0;
    int fds[VHOST_MEMORY_MAX_NREGIONS];
    size_t fd_num = 0;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);

    if (fd < 0) {
        return 0;
    }

    msg.request = VHOST_USER_NONE;
    msg.flags = VHOST_USER_VERSION;
    msg.size = 0;

    switch (request) {
    default:
        error_report("vhost-user trying to send unhandled ioctl\n");
        return -1;
        break;
    }

    result = vhost_user_send_fds(fd, &msg, fds, fd_num);

    return result;
}

static int vhost_user_init(struct vhost_dev *dev, const char *devpath)
{
    int fd = -1;
    struct sockaddr_un un;
    struct timeval tv;
    size_t len;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);

    /* Create the socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        error_report("socket: %s", strerror(errno));
        return -1;
    }

    /* Set socket options */
    tv.tv_sec = VHOST_USER_SOCKTO / 1000;
    tv.tv_usec = (VHOST_USER_SOCKTO % 1000) * 1000;

    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval))
            == -1) {
        error_report("setsockopt SO_SNDTIMEO: %s", strerror(errno));
        goto fail;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval))
            == -1) {
        error_report("setsockopt SO_RCVTIMEO: %s", strerror(errno));
        goto fail;
    }

    /* Connect */
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, devpath);

    len = sizeof(un.sun_family) + strlen(devpath);

    if (connect(fd, (struct sockaddr *) &un, len) == -1) {
        error_report("connect: %s", strerror(errno));
        goto fail;
    }

    /* Cleanup if there is previous connection left */
    if (dev->control >= 0) {
        dev->vhost_ops->vhost_backend_cleanup(dev);
    }
    dev->control = fd;

    if (vhost_user_echo(dev) < 0) {
        dev->control = -1;
        goto fail;
    }

    return fd;

fail:
    close(fd);
    return -1;

}

static int vhost_user_cleanup(struct vhost_dev *dev)
{
    int r = 0;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);

    if (dev->control >= 0) {
        r = close(dev->control);
    }
    dev->control = -1;

    return r;
}

static const VhostOps user_ops = {
        .backend_type = VHOST_BACKEND_TYPE_USER,
        .vhost_call = vhost_user_call,
        .vhost_backend_init = vhost_user_init,
        .vhost_backend_cleanup = vhost_user_cleanup
};

static int vhost_kernel_call(struct vhost_dev *dev, unsigned long int request,
                             void *arg)
{
    int fd = dev->control;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    return ioctl(fd, request, arg);
}

static int vhost_kernel_init(struct vhost_dev *dev, const char *devpath)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    dev->control = open(devpath, O_RDWR);
    return dev->control;
}

static int vhost_kernel_cleanup(struct vhost_dev *dev)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    return close(dev->control);
}

static const VhostOps kernel_ops = {
        .backend_type = VHOST_BACKEND_TYPE_KERNEL,
        .vhost_call = vhost_kernel_call,
        .vhost_backend_init = vhost_kernel_init,
        .vhost_backend_cleanup = vhost_kernel_cleanup
};

int vhost_set_backend_type(struct vhost_dev *dev, VhostBackendType backend_type)
{
    int r = 0;

    switch (backend_type) {
    case VHOST_BACKEND_TYPE_KERNEL:
        dev->vhost_ops = &kernel_ops;
        break;
    case VHOST_BACKEND_TYPE_USER:
        dev->vhost_ops = &user_ops;
        break;
    default:
        error_report("Unknown vhost backend type\n");
        r = -1;
    }

    return r;
}

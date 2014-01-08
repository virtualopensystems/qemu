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
    __u64 guest_phys_addr;
    __u64 memory_size;
    __u64 userspace_addr;
} VhostUserMemoryRegion;

typedef struct VhostUserMemory {
    __u32 nregions;
    __u32 padding;
    VhostUserMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostUserMemory;

typedef struct VhostUserMsg {
    VhostUserRequest request;

#define VHOST_USER_VERSION_MASK     (0x3)
#define VHOST_USER_REPLY_MASK       (0x1<<2)
    __u32 flags;
    __u32 size; /* the following payload size */
    union {
        __u64 u64;
        int fd;
        struct vhost_vring_state state;
        struct vhost_vring_addr addr;
        struct vhost_vring_file file;
        VhostUserMemory memory;
    };
} QEMU_PACKED VhostUserMsg;

#define MEMB_SIZE(t, m)     (sizeof(((t *)0)->m))
#define VHOST_USER_HDR_SIZE (MEMB_SIZE(VhostUserMsg, request) \
                            + MEMB_SIZE(VhostUserMsg, flags) \
                            + MEMB_SIZE(VhostUserMsg, size))

/* The version of the protocol we support */
#define VHOST_USER_VERSION    (0x1)

static unsigned long int ioctl_to_vhost_user_request[VHOST_USER_MAX] = {
    -1, /* VHOST_USER_NONE */
    VHOST_GET_FEATURES, /* VHOST_USER_GET_FEATURES */
    VHOST_SET_FEATURES, /* VHOST_USER_SET_FEATURES */
    VHOST_SET_OWNER, /* VHOST_USER_SET_OWNER */
    VHOST_RESET_OWNER, /* VHOST_USER_RESET_OWNER */
    VHOST_SET_MEM_TABLE, /* VHOST_USER_SET_MEM_TABLE */
    VHOST_SET_LOG_BASE, /* VHOST_USER_SET_LOG_BASE */
    VHOST_SET_LOG_FD, /* VHOST_USER_SET_LOG_FD */
    VHOST_SET_VRING_NUM, /* VHOST_USER_SET_VRING_NUM */
    VHOST_SET_VRING_ADDR, /* VHOST_USER_SET_VRING_ADDR */
    VHOST_SET_VRING_BASE, /* VHOST_USER_SET_VRING_BASE */
    VHOST_GET_VRING_BASE, /* VHOST_USER_GET_VRING_BASE */
    VHOST_SET_VRING_KICK, /* VHOST_USER_SET_VRING_KICK */
    VHOST_SET_VRING_CALL, /* VHOST_USER_SET_VRING_CALL */
    VHOST_SET_VRING_ERR, /* VHOST_USER_SET_VRING_ERR */
    VHOST_NET_SET_BACKEND, /* VHOST_USER_NET_SET_BACKEND */
    -1 /* VHOST_USER_ECHO */
};

static int vhost_user_cleanup(struct vhost_dev *dev);

static VhostUserRequest vhost_user_request_translate(unsigned long int request)
{
    VhostUserRequest idx;

    for (idx = 0; idx < VHOST_USER_MAX; idx++) {
        if (ioctl_to_vhost_user_request[idx] == request) {
            break;
        }
    }

    return (idx == VHOST_USER_MAX) ? VHOST_USER_NONE : idx;
}

static int vhost_user_recv(int fd, VhostUserMsg *msg)
{
    ssize_t r;
    __u8 *p = (__u8 *)msg;

    /* read the header */
    do {
        r = read(fd, p, VHOST_USER_HDR_SIZE);
    } while (r < 0 && errno == EINTR);

    if (r > 0) {
        p += VHOST_USER_HDR_SIZE;
        /* read the payload */
        do {
            r = read(fd, p, msg->size);
        } while (r < 0 && errno == EINTR);
    }

    if (r < 0) {
        error_report("Failed to read msg, reason: %s\n", strerror(errno));
    }

    return (r < 0) ? -1 : 0;
}

static int vhost_user_send_fds(int fd, const VhostUserMsg *msg, int *fds,
        size_t fd_num)
{
    int r;

    struct msghdr msgh;
    struct iovec iov[1];

    size_t fd_size = fd_num * sizeof(int);
    char control[CMSG_SPACE(fd_size)];
    struct cmsghdr *cmsg;

    memset(&msgh, 0, sizeof(msgh));
    memset(control, 0, sizeof(control));

    /* set the payload */
    iov[0].iov_base = (void *)msg;
    iov[0].iov_len = VHOST_USER_HDR_SIZE + msg->size;

    msgh.msg_iov = iov;
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
    } else {
        r = 0;
    }

    return r;
}

static int vhost_user_echo(struct vhost_dev *dev)
{
    VhostUserMsg msg;
    int fd = dev->control;

    if (fd < 0) {
        return -1;
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

    if ((msg.flags & VHOST_USER_REPLY_MASK) == 0 ||
        (msg.flags & VHOST_USER_VERSION_MASK) != VHOST_USER_VERSION) {
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
    RAMBlock *block = 0;
    int result = 0, need_reply = 0;
    int fds[VHOST_MEMORY_MAX_NREGIONS];
    size_t fd_num = 0;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);

    if (fd < 0) {
        return -1;
    }

    msg.request = vhost_user_request_translate(request);
    msg.flags = VHOST_USER_VERSION;
    msg.size = 0;

    switch (request) {
    case VHOST_GET_FEATURES:
    case VHOST_GET_VRING_BASE:
        need_reply = 1;
        break;

    case VHOST_SET_FEATURES:
    case VHOST_SET_LOG_BASE:
        msg.u64 = *((__u64 *) arg);
        msg.size = MEMB_SIZE(VhostUserMsg, u64);
        break;

    case VHOST_SET_OWNER:
    case VHOST_RESET_OWNER:
        break;

    case VHOST_SET_MEM_TABLE:
        QTAILQ_FOREACH(block, &ram_list.blocks, next)
        {
            if (block->fd > 0) {
                msg.memory.regions[fd_num].userspace_addr = (__u64) block->host;
                msg.memory.regions[fd_num].memory_size = block->length;
                msg.memory.regions[fd_num].guest_phys_addr = block->offset;
                fds[fd_num++] = block->fd;
            }
        }

        msg.memory.nregions = fd_num;

        if (!fd_num) {
            error_report("Failed initializing vhost-user memory map\n"
                    "consider using -mem-path option\n");
            return -1;
        }

        msg.size = MEMB_SIZE(VhostUserMemory, nregions);
        msg.size += MEMB_SIZE(VhostUserMemory, padding);
        msg.size += fd_num*sizeof(VhostUserMemoryRegion);

        break;

    case VHOST_SET_LOG_FD:
        msg.fd = *((int *) arg);
        msg.size = MEMB_SIZE(VhostUserMsg, fd);
        break;

    case VHOST_SET_VRING_NUM:
    case VHOST_SET_VRING_BASE:
        memcpy(&msg.state, arg, sizeof(struct vhost_vring_state));
        msg.size = MEMB_SIZE(VhostUserMsg, state);
        break;

    case VHOST_SET_VRING_ADDR:
        memcpy(&msg.addr, arg, sizeof(struct vhost_vring_addr));
        msg.size = MEMB_SIZE(VhostUserMsg, addr);
        break;

    case VHOST_SET_VRING_KICK:
    case VHOST_SET_VRING_CALL:
    case VHOST_SET_VRING_ERR:
    case VHOST_NET_SET_BACKEND:
        memcpy(&msg.file, arg, sizeof(struct vhost_vring_file));
        msg.size = MEMB_SIZE(VhostUserMsg, file);
        if (msg.file.fd > 0) {
            fds[0] = msg.file.fd;
            fd_num = 1;
        }
        break;
    default:
        error_report("vhost-user trying to send unhandled ioctl\n");
        return -1;
        break;
    }

    result = vhost_user_send_fds(fd, &msg, fds, fd_num);

    if (!result && need_reply) {
        result = vhost_user_recv(fd, &msg);

        if ((msg.flags & VHOST_USER_REPLY_MASK) == 0 ||
            (msg.flags & VHOST_USER_VERSION_MASK) != VHOST_USER_VERSION) {
            error_report("Received bad msg.\n");
            return -1;
        }

        if (!result) {
            switch (request) {
            case VHOST_GET_FEATURES:
                if (msg.size != MEMB_SIZE(VhostUserMsg, u64)) {
                    error_report("Received bad msg.\n");
                    return -1;
                }
                *((__u64 *) arg) = msg.u64;
                break;
            case VHOST_GET_VRING_BASE:
                if (msg.size != MEMB_SIZE(VhostUserMsg, state)) {
                    error_report("Received bad msg.\n");
                    return -1;
                }
                memcpy(arg, &msg.state, sizeof(struct vhost_vring_state));
                break;
            }
        }
    }

    /* mark the backend non operational */
    if (result < 0) {
        error_report("%s: Connection break detected\n", __func__);
        vhost_user_cleanup(dev);
        return 0;
    }

    return result;
}

static int vhost_user_status(struct vhost_dev *dev)
{
    vhost_user_echo(dev);

    return (dev->control >= 0);
}

static int vhost_user_init(struct vhost_dev *dev, const char *devpath)
{
    int fd = -1;
    struct sockaddr_un un;
    struct timeval tv;
    size_t len;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);

    /* Create the socket */
    fd = qemu_socket(AF_UNIX, SOCK_STREAM, 0);
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
        vhost_user_cleanup(dev);
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
        .vhost_status = vhost_user_status,
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
        .vhost_status = 0,
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

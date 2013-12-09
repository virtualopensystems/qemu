/*
 * vhost-backend
 *
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-backend.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/vhost.h>

#define VHOST_MEMORY_MAX_NREGIONS    8

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
    VHOST_USER_MAX
} VhostUserRequest;

typedef struct VhostUserMemoryRegion {
    __u64 guest_phys_addr;
    __u64 memory_size;
    __u64 userspace_addr;
} VhostUserMemoryRegion;

typedef struct VhostUserMemory {
    __u32 nregions;
    VhostUserMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostUserMemory;

typedef struct VhostUserMsg {
    VhostUserRequest request;

    int flags;
    union {
        uint64_t    u64;
        int         fd;
        struct vhost_vring_state state;
        struct vhost_vring_addr addr;
        struct vhost_vring_file file;

        VhostUserMemory memory;
    };
} VhostUserMsg;

static int vhost_user_recv(int fd, VhostUserMsg *msg)
{
    ssize_t r = read(fd, msg, sizeof(VhostUserMsg));

    return (r == sizeof(VhostUserMsg)) ? 0 : -1;
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
    iov[0].iov_base = (void *) msg;
    iov[0].iov_len = sizeof(VhostUserMsg);

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
        fprintf(stderr, "Failed to send msg(%d), reason: %s\n",
                msg->request, strerror(errno));
    } else {
        r = 0;
    }

    return r;
}

static int vhost_user_call(struct vhost_dev *dev, unsigned long int request,
        void *arg)
{
    int fd = dev->control;
    VhostUserMsg msg;
    int result = 0, need_reply = 0;
    int fds[VHOST_MEMORY_MAX_NREGIONS];
    size_t fd_num = 0;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);

    switch (request) {
    default:
        fprintf(stderr, "vhost-user trying to send unhandled ioctl\n");
        return -1;
        break;
    }

    result = vhost_user_send_fds(fd, &msg, fds, fd_num);

    if (!result && need_reply) {
        result = vhost_user_recv(fd, &msg);
        if (!result) {
            switch (request) {
            default:
                break;
            }
        }
    }

    return result;
}

static int vhost_user_init(struct vhost_dev *dev, const char *devpath)
{
    int fd = -1;
    struct sockaddr_un un;
    size_t len;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);

    /* Create the socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, devpath);

    len = sizeof(un.sun_family) + strlen(devpath);

    /* Connect */
    if (connect(fd, (struct sockaddr *) &un, len) == -1) {
        perror("connect");
        return -1;
    }

    dev->control = fd;

    return fd;
}

static int vhost_user_cleanup(struct vhost_dev *dev)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);

    return close(dev->control);
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
        fprintf(stderr, "Unknown vhost backend type\n");
        r = -1;
    }

    return r;
}

/*
 * vhost-backend
 *
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 * Written by Nikolay Nikolaev <n.nikolaev@virtualopensystems.com>
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
    int ret;

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
        ret = sendmsg(fd, &msgh, 0);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) {
        fprintf(stderr, "Failed to send msg(%d), reason: %s\n",
                msg->request, strerror(errno));
    } else {
        ret = 0;
    }

    return ret;
}

static int vhost_kernel_call(struct vhost_dev *dev, unsigned long int request,
        void *arg)
{
    int fd = dev->control;
    return ioctl(fd, request, arg);
}

static int vhost_user_call(struct vhost_dev *dev, unsigned long int request,
        void *arg)
{
    int fd = dev->control;
    VhostUserMsg msg;
    int result = 0;
    int fds[VHOST_MEMORY_MAX_NREGIONS];
    size_t fd_num = 0;

    memset(&msg, 0, sizeof(VhostUserMsg));

    switch (request) {
    default:
        fprintf(stderr, "vhost-user trying to send unhandled ioctl\n");
        return -1;
        break;
    }

    result = vhost_user_send_fds(fd, &msg, fds, fd_num);

    if (!result) {
        result = vhost_user_recv(fd, &msg);
        if (!result) {
            switch (request) {
            default:
                fprintf(stderr, "vhost-user received unhandled message\n");
            }
        }
    }

    return result;
}

int vhost_call(struct vhost_dev *dev, unsigned long int request, void *arg)
{
    int result = -1;

    switch (dev->backend_type) {
    case VHOST_BACKEND_TYPE_KERNEL:
        result = vhost_kernel_call(dev, request, arg);
        break;
    case VHOST_BACKEND_TYPE_USER:
        result = vhost_user_call(dev, request, arg);
        break;
    default:
        fprintf(stderr, "Unknown vhost backend type\n");
    }

    return result;
}

int vhost_backend_init(struct vhost_dev *dev, const char *devpath)
{
    int fd = -1;
    struct sockaddr_un un;
    size_t len;

    switch (dev->backend_type) {
    case VHOST_BACKEND_TYPE_KERNEL:
        fd = open(devpath, O_RDWR);
        break;
    case VHOST_BACKEND_TYPE_USER:
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
        break;
    default:
        fprintf(stderr, "Unknown vhost backend type\n");
    }

    dev->control = fd;

    return fd;
}

int vhost_backend_cleanup(struct vhost_dev *dev)
{
    return close(dev->control);
}

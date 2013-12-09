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

static int vhost_user_call(struct vhost_dev *dev, unsigned long int request,
        void *arg)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);
    fprintf(stderr, "vhost_user_call not implemented\n");

    return -1;
}

static int vhost_user_init(struct vhost_dev *dev, const char *devpath)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);
    fprintf(stderr, "vhost_user_init not implemented\n");

    return -1;
}

static int vhost_user_cleanup(struct vhost_dev *dev)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_USER);
    fprintf(stderr, "vhost_user_cleanup not implemented\n");

    return -1;
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

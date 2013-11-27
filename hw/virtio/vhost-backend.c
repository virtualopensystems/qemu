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

static int vhost_kernel_call(struct vhost_dev *dev, unsigned long int request,
        void *arg)
{
    int fd = dev->control;
    return ioctl(fd, request, arg);
}

int vhost_call(struct vhost_dev *dev, unsigned long int request, void *arg)
{
    int result;

    result = vhost_kernel_call(dev, request, arg);

    return result;
}

int vhost_backend_init(struct vhost_dev *dev, const char *devpath)
{
    int fd = -1;

    fd = open(devpath, O_RDWR);
    dev->control = fd;

    return fd;
}

int vhost_backend_cleanup(struct vhost_dev *dev)
{
    return close(dev->control);
}

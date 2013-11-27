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

#ifndef VHOST_BACKEND_H_
#define VHOST_BACKEND_H_

struct vhost_dev;
int vhost_call(struct vhost_dev *dev, unsigned long int request, void *arg);

int vhost_backend_init(struct vhost_dev *dev, const char *devpath);
int vhost_backend_cleanup(struct vhost_dev *dev);

#endif /* VHOST_BACKEND_H_ */

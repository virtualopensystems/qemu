/*
 * vhost-user.c
 *
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "clients.h"
#include "net/vhost_net.h"
#include "net/vhost-user.h"
#include "qemu/error-report.h"

typedef struct VhostUserState {
    NetClientState nc;
    VHostNetState *vhost_net;
} VhostUserState;

VHostNetState *vhost_user_get_vhost_net(NetClientState *nc)
{
    VhostUserState *s = DO_UPCAST(VhostUserState, nc, nc);
    assert(nc->info->type == NET_CLIENT_OPTIONS_KIND_VHOST_USER);
    return s->vhost_net;
}

static void vhost_user_cleanup(NetClientState *nc)
{
    VhostUserState *s = DO_UPCAST(VhostUserState, nc, nc);

    if (s->vhost_net) {
        vhost_net_cleanup(s->vhost_net);
        s->vhost_net = NULL;
    }

    qemu_purge_queued_packets(nc);
}

static NetClientInfo net_vhost_user_info = {
        .type = NET_CLIENT_OPTIONS_KIND_VHOST_USER,
        .size = sizeof(VhostUserState),
        .cleanup = vhost_user_cleanup,
};

static int net_vhost_user_init(NetClientState *peer, const char *device,
                          const char *name, const char *filename)
{
    NetClientState *nc;
    VhostUserState *s;
    VhostNetOptions options;

    nc = qemu_new_net_client(&net_vhost_user_info, peer, device, name);

    snprintf(nc->info_str, sizeof(nc->info_str), "vhost-user to %s", filename);

    s = DO_UPCAST(VhostUserState, nc, nc);

    options.backend_type = VHOST_BACKEND_TYPE_USER;
    options.net_backend = &s->nc;
    options.devpath = filename;
    options.devfd = -1;
    options.force = 0;

    s->vhost_net = vhost_net_init(&options);

    if (!s->vhost_net) {
        error_report("vhost-net requested but could not be initialized");
        return -1;
    }

    /* We don't provide a receive callback */
    s->nc.receive_disabled = 0;

    return 0;
}

int net_init_vhost_user(const NetClientOptions *opts, const char *name,
                   NetClientState *peer)
{
    const char *file;
    const NetdevVhostUserOptions *vhost_user;

    assert(opts->kind == NET_CLIENT_OPTIONS_KIND_VHOST_USER);
    vhost_user = opts->vhost_user;

    if (vhost_user->has_file) {
        file = vhost_user->file;
    } else {
        fprintf(stderr, "file has to be specified");
        return -1;
    }

    return net_vhost_user_init(peer, "vhost_user", name, file);
}

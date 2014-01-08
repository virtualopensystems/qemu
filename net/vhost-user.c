/*
 * vhost-user.c
 *
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "clients.h"
#include "net/vhost_net.h"
#include "net/vhost-user.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"

typedef struct VhostUserState {
    NetClientState nc;
    VHostNetState *vhost_net;
    char *devpath;
} VhostUserState;

static QEMUTimer *vhost_user_timer;
#define VHOST_USER_TIMEOUT  (1*1000)

VHostNetState *vhost_user_get_vhost_net(NetClientState *nc)
{
    VhostUserState *s = DO_UPCAST(VhostUserState, nc, nc);
    assert(nc->info->type == NET_CLIENT_OPTIONS_KIND_VHOST_USER);
    return s->vhost_net;
}

static int vhost_user_running(VhostUserState *s)
{
    return (s->vhost_net) ? 1 : 0;
}

static int vhost_user_link_status(VhostUserState *s)
{
    return (!s->nc.link_down) && vhost_net_link_status(s->vhost_net);
}

static int vhost_user_start(VhostUserState *s)
{
    VhostNetOptions options;

    if (vhost_user_running(s)) {
        return 1;
    }

    options.backend_type = VHOST_BACKEND_TYPE_USER;
    options.net_backend = &s->nc;
    options.devpath = s->devpath;
    options.devfd = -1;
    options.force = 1;

    s->vhost_net = vhost_net_init(&options);

    return vhost_user_running(s) ? 0 : -1;
}

static void vhost_user_stop(VhostUserState *s)
{
    if (vhost_user_running(s)) {
        vhost_net_cleanup(s->vhost_net);
    }

    s->vhost_net = 0;
}

static void vhost_user_timer_handler(void *opaque)
{
    VhostUserState *s = opaque;
    int link_down = 0;

    if (vhost_user_running(s)) {
        if (!vhost_user_link_status(s)) {
            link_down = 1;
        }
    } else {
        vhost_user_start(s);
        if (!vhost_user_running(s)) {
            link_down = 1;
        }
    }

    if (link_down != s->nc.link_down) {

        s->nc.link_down = link_down;

        if (s->nc.peer) {
            s->nc.peer->link_down = link_down;
        }

        if (s->nc.info->link_status_changed) {
            s->nc.info->link_status_changed(&s->nc);
        }

        if (s->nc.peer && s->nc.peer->info->link_status_changed) {
            s->nc.peer->info->link_status_changed(s->nc.peer);
        }

        if (link_down) {
            vhost_user_stop(s);
        }
    }

    /* reschedule */
    timer_mod(vhost_user_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + VHOST_USER_TIMEOUT);
}

static void vhost_user_cleanup(NetClientState *nc)
{
    VhostUserState *s = DO_UPCAST(VhostUserState, nc, nc);

    vhost_user_stop(s);
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
    int r;

    nc = qemu_new_net_client(&net_vhost_user_info, peer, device, name);

    snprintf(nc->info_str, sizeof(nc->info_str), "vhost-user to %s", filename);

    s = DO_UPCAST(VhostUserState, nc, nc);

    /* We don't provide a receive callback */
    s->nc.receive_disabled = 1;

    s->devpath = g_strdup(filename);

    r = vhost_user_start(s);

    vhost_user_timer = timer_new_ms(QEMU_CLOCK_REALTIME,
            vhost_user_timer_handler, s);
    timer_mod(vhost_user_timer,
            qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + VHOST_USER_TIMEOUT);

    return r;
}

int net_init_vhost_user(const NetClientOptions *opts, const char *name,
                   NetClientState *peer)
{
    const char *file;
    const NetdevVhostUserOptions *vhost_user;

    assert(opts->kind == NET_CLIENT_OPTIONS_KIND_VHOST_USER);
    vhost_user = opts->vhost_user;

    file = vhost_user->file;

    return net_vhost_user_init(peer, "vhost_user", name, file);
}

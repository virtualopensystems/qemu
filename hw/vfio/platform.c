/*
 * vfio based device assignment support - platform devices
 *
 * Copyright Linaro Limited, 2014
 *
 * Authors:
 *  Kim Phillips <kim.phillips@linaro.org>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on vfio based PCI device assignment support:
 *  Copyright Red Hat, Inc. 2012
 */

#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "qemu/error-report.h"
#include "qemu/range.h"
#include "sysemu/sysemu.h"
#include "hw/sysbus.h"

#include "vfio-common.h"

typedef struct VFIOINTp {
    QLIST_ENTRY(VFIOINTp) next; /* entry for IRQ list */
    QSIMPLEQ_ENTRY(VFIOINTp) pqnext; /* entry for pending IRQ queue */
    EventNotifier interrupt; /* eventfd triggered on interrupt */
    EventNotifier unmask; /* eventfd for unmask on QEMU bypass */
    qemu_irq qemuirq;
    struct VFIOPlatformDevice *vdev; /* back pointer to device */
    int state; /* inactive, pending, active */
    bool kvm_accel; /* set when QEMU bypass through KVM enabled */
    uint8_t pin; /* index */
} VFIOINTp;


typedef struct VFIOPlatformDevice {
    SysBusDevice sbdev;
    VFIODevice vdev; /* not a QOM object */
    QLIST_HEAD(, VFIOINTp) intp_list; /* list of IRQ */
    /* queue of pending IRQ */
    QSIMPLEQ_HEAD(pending_intp_queue, VFIOINTp) pending_intp_queue;
} VFIOPlatformDevice;


static const MemoryRegionOps vfio_region_ops = {
    .read = vfio_region_read,
    .write = vfio_region_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void vfio_intp_interrupt(void *opaque);

/*
 * It is mandatory to pass a VFIOPlatformDevice since VFIODevice
 * is not a QOM Object and cannot be passed to memory region functions
*/

static void vfio_map_region(VFIOPlatformDevice *vdev, int nr)
{
    VFIORegion *region = vdev->vdev.regions[nr];
    unsigned size = region->size;
    char name[64];

    snprintf(name, sizeof(name), "VFIO %s region %d", vdev->vdev.name, nr);

    /* A "slow" read/write mapping underlies all regions */
    memory_region_init_io(&region->mem, OBJECT(vdev), &vfio_region_ops,
                          region, name, size);

    strncat(name, " mmap", sizeof(name) - strlen(name) - 1);

    if (vfio_mmap_region(OBJECT(vdev), region, &region->mem,
                         &region->mmap_mem, &region->mmap, size, 0, name)) {
        error_report("%s unsupported. Performance may be slow", name);
    }
}


static void vfio_unmap_region(VFIODevice *vdev, int nr)
{
    VFIORegion *region = vdev->regions[nr];

    if (!region->size) {
        return;
    }

    memory_region_del_subregion(&region->mem, &region->mmap_mem);
    munmap(region->mmap, memory_region_size(&region->mmap_mem));
    memory_region_destroy(&region->mmap_mem);

    memory_region_destroy(&region->mem);
}

static void vfio_unmap_regions(VFIODevice *vdev)
{
    int i;
    for (i = 0; i < vdev->num_regions; i++) {
        vfio_unmap_region(vdev, i);
    }
}


static int vfio_platform_get_device_regions(VFIODevice *vbasedev)
{
    struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };
    int i, ret = errno;

    vbasedev->regions = g_malloc0(sizeof(VFIORegion *) * vbasedev->num_regions);

    for (i = 0; i < vbasedev->num_regions; i++) {
        vbasedev->regions[i] = g_malloc0(sizeof(VFIORegion));

        reg_info.index = i;

        ret = ioctl(vbasedev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
        if (ret) {
            error_report("vfio: Error getting region %d info: %m", i);
            goto error;
        }

        vbasedev->regions[i]->flags = reg_info.flags;
        vbasedev->regions[i]->size = reg_info.size;
        vbasedev->regions[i]->fd_offset = reg_info.offset;
        vbasedev->regions[i]->fd = vbasedev->fd;
        vbasedev->regions[i]->nr = i;
        vbasedev->regions[i]->vdev = vbasedev;
    }

    print_regions(vbasedev);

    return ret;

error:
    for (i = 0; i < vbasedev->num_regions; i++) {
            g_free(vbasedev->regions[i]);
    }
    g_free(vbasedev->regions);
    vfio_put_base_device(vbasedev);
    return ret;
}


/* not implemented yet */
static int vfio_platform_check_device(VFIODevice *vdev)
{
    return 0;
}

/* not implemented yet */
static bool vfio_platform_compute_needs_reset(VFIODevice *vdev)
{
return false;
}

static int vfio_platform_hot_reset_multi(VFIODevice *vdev)
{
return 0;
}

/*
 * eoi function is called on the first access to any MMIO region
 * after an IRQ was triggered. It is assumed this access corresponds
 * to the IRQ status register reset.
 * With such a mechanism, a single IRQ can be handled at a time since
 * there is no way to know which IRQ was completed by the guest.
 * (we would need additional details about the IRQ status register mask)
 */

static void vfio_platform_eoi(VFIODevice *vdev)
{
    VFIOINTp *intp;
    VFIOPlatformDevice *vplatdev = container_of(vdev, VFIOPlatformDevice, vdev);
    bool eoi_done = false;

    QLIST_FOREACH(intp, &vplatdev->intp_list, next) {
        if (intp->state == VFIO_IRQ_ACTIVE) {
            if (eoi_done) {
                error_report("several IRQ pending: "
                             "this case should not happen!\n");
            }
            DPRINTF("EOI IRQ #%d fd=%d\n",
                    intp->pin, event_notifier_get_fd(&intp->interrupt));
            intp->state = VFIO_IRQ_INACTIVE;

            /* deassert the virtual IRQ and unmask physical one */
            qemu_set_irq(intp->qemuirq, 0);
            vfio_unmask_irqindex(vdev, intp->pin);
            eoi_done = true;
        }
    }

    /*
     * in case there are pending IRQs, handle them one at a time */
     if (!QSIMPLEQ_EMPTY(&vplatdev->pending_intp_queue)) {
            intp = QSIMPLEQ_FIRST(&vplatdev->pending_intp_queue);
            vfio_intp_interrupt(intp);
            QSIMPLEQ_REMOVE_HEAD(&vplatdev->pending_intp_queue, pqnext);
     }

    return;
}

/*
 * enable/disable the fast path mode
 * fast path = MMIO region is mmaped (no KVM TRAP)
 * slow path = MMIO region is trapped and region callbacks are called
 * slow path enables to trap the IRQ status register guest reset
*/

static void vfio_mmap_set_enabled(VFIODevice *vdev, bool enabled)
{
    VFIORegion *region;
    int i;

    DPRINTF("fast path = %d\n", enabled);

    for (i = 0; i < vdev->num_regions; i++) {
        region = vdev->regions[i];

        /* register space is unmapped to trap EOI */
        memory_region_set_enabled(&region->mmap_mem, enabled);
    }
}

/*
 * Checks whether the IRQ is still pending. In the negative
 * the fast path mode (where reg space is mmaped) can be restored.
 * if the IRQ is still pending, we must keep on trapping IRQ status
 * register reset with mmap disabled (slow path).
 * the function is called on mmap_timer event.
 * by construction a single fd is handled at a time. See EOI comment
 * for additional details.
 */


static void vfio_intp_mmap_enable(void *opaque)
{
    VFIOINTp *tmp;
    VFIODevice *vdev = (VFIODevice *)opaque;
    VFIOPlatformDevice *vplatdev = container_of(vdev, VFIOPlatformDevice, vdev);
    bool one_active_irq = false;

    QLIST_FOREACH(tmp, &vplatdev->intp_list, next) {
        if (tmp->state == VFIO_IRQ_ACTIVE) {
            if (one_active_irq) {
                error_report("several active IRQ: "
                             "this case should not happen!\n");
            }
            DPRINTF("IRQ #%d still pending, stay in slow path\n",
                    tmp->pin);
            timer_mod(vdev->mmap_timer,
                          qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                          vdev->mmap_timeout);
            one_active_irq = true;
        }
    }
    if (one_active_irq) {
        return;
    }

    DPRINTF("no pending IRQ, restore fast path\n");
    vfio_mmap_set_enabled(vdev, true);
}

/*
 * The fd handler
 */

static void vfio_intp_interrupt(void *opaque)
{
    int ret;
    VFIOINTp *tmp, *intp = (VFIOINTp *)opaque;
    VFIOPlatformDevice *vplatdev = intp->vdev;
    VFIODevice *vdev = &vplatdev->vdev;
    bool one_active_irq = false;

    /*
     * first check whether there is a pending IRQ
     * in the positive the new IRQ cannot be handled until the
     * active one is not completed.
     * by construction the same IRQ as the pending one cannot hit
     * since the physical IRQ was disabled by the VFIO driver
     */
    QLIST_FOREACH(tmp, &vplatdev->intp_list, next) {
        if (tmp->state == VFIO_IRQ_ACTIVE) {
            one_active_irq = true;
        }
    }
    if (one_active_irq) {
        /*
         * the new IRQ gets a pending status and is pushed in
         * the pending queue
         */
        intp->state = VFIO_IRQ_PENDING;
        QSIMPLEQ_INSERT_TAIL(&vplatdev->pending_intp_queue,
                             intp, pqnext);
        return;
    }

    /* no active IRQ, the new IRQ can be forwarded to guest */
    DPRINTF("Handle IRQ #%d (fd = %d)\n",
            intp->pin, event_notifier_get_fd(&intp->interrupt));

    ret = event_notifier_test_and_clear(&intp->interrupt);
    if (!ret) {
        DPRINTF("Error when clearing fd=%d\n",
                event_notifier_get_fd(&intp->interrupt));
    }

    intp->state = VFIO_IRQ_ACTIVE;

    /* sets slow path */
    vfio_mmap_set_enabled(vdev, false);

    /* trigger the virtual IRQ */
    qemu_set_irq(intp->qemuirq, 1);

    /* schedule the mmap timer which will restore mmap path after EOI*/
    if (vdev->mmap_timeout) {
        timer_mod(vdev->mmap_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + vdev->mmap_timeout);
    }

}

static int vfio_enable_intp(VFIODevice *vdev, unsigned int index)
{
    struct vfio_irq_set *irq_set;
    int32_t *pfd;
    int ret, argsz;
    int device = vdev->fd;
    VFIOPlatformDevice *vplatdev = container_of(vdev, VFIOPlatformDevice, vdev);
    SysBusDevice *sbdev = SYS_BUS_DEVICE(vplatdev);

    /* allocate and populate a new VFIOINTp structure put in a queue list */
    VFIOINTp *intp = g_malloc0(sizeof(*intp));
    intp->vdev = vplatdev;
    intp->pin = index;
    intp->state = VFIO_IRQ_INACTIVE;

    sysbus_init_irq(sbdev, &intp->qemuirq);

    ret = event_notifier_init(&intp->interrupt, 0);
    if (ret) {
        error_report("vfio: Error: event_notifier_init failed ");
        return ret;
    }
    /* build the irq_set to be passed to the vfio kernel driver */

    argsz = sizeof(*irq_set) + sizeof(*pfd);

    irq_set = g_malloc0(argsz);
    irq_set->argsz = argsz;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = index;
    irq_set->start = 0;
    irq_set->count = 1;
    pfd = (int32_t *)&irq_set->data;

    *pfd = event_notifier_get_fd(&intp->interrupt);

    DPRINTF("register fd=%d/irq index=%d to kernel\n", *pfd, index);

    qemu_set_fd_handler(*pfd, vfio_intp_interrupt, NULL, intp);

    /*
     * pass the index/fd binding to the kernel driver so that it
     * triggers this fd on HW IRQ
     */
    ret = ioctl(device, VFIO_DEVICE_SET_IRQS, irq_set);
    g_free(irq_set);
    if (ret) {
        error_report("vfio: Error: Failed to pass IRQ fd to the driver: %m");
        qemu_set_fd_handler(*pfd, NULL, NULL, NULL);
        close(*pfd); /* TO DO : replace by event_notifier_cleanup */
        return -errno;
    }

    /* store the new intp in qlist */

    QLIST_INSERT_HEAD(&vplatdev->intp_list, intp, next);

    return 0;
}


static int vfio_platform_get_device_interrupts(VFIODevice *vdev)
{
    struct vfio_irq_info irq = { .argsz = sizeof(irq) };
    int i, ret;
    VFIOPlatformDevice *vplatdev = container_of(vdev, VFIOPlatformDevice, vdev);

    /*
     * mmap timeout = 1100 ms, PCI default value
     * this will become a user-defined value in subsequent patch
     */
    vdev->mmap_timeout = 1100;
    vdev->mmap_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                    vfio_intp_mmap_enable, vdev);

    QSIMPLEQ_INIT(&vplatdev->pending_intp_queue);

    for (i = 0; i < vdev->num_irqs; i++) {
        irq.index = i;

        DPRINTF("Retrieve IRQ info from vfio platform driver ...\n");

        ret = ioctl(vdev->fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);
        if (ret) {
            error_printf("vfio: error getting device %s irq info",
                         vdev->name);
        }
        DPRINTF("- IRQ index %d: count %d, flags=0x%x\n",
                irq.index, irq.count, irq.flags);

        vfio_enable_intp(vdev, irq.index);
    }
    return 0;
}


static void vfio_disable_intp(VFIODevice *vdev)
{
    VFIOINTp *intp;
    VFIOPlatformDevice *vplatdev = container_of(vdev, VFIOPlatformDevice, vdev);
    int fd;

    QLIST_FOREACH(intp, &vplatdev->intp_list, next) {
        fd = event_notifier_get_fd(&intp->interrupt);
        DPRINTF("close IRQ pin=%d fd=%d\n", intp->pin, fd);

        vfio_disable_irqindex(vdev, intp->pin);
        intp->state = VFIO_IRQ_INACTIVE;
        qemu_set_irq(intp->qemuirq, 0);

        qemu_set_fd_handler(fd, NULL, NULL, NULL);
        event_notifier_cleanup(&intp->interrupt);
    }

    /* restore fast path */
    vfio_mmap_set_enabled(vdev, true);

}


static VFIODeviceOps vfio_platform_ops = {
    .vfio_eoi = vfio_platform_eoi,
    .vfio_compute_needs_reset = vfio_platform_compute_needs_reset,
    .vfio_hot_reset_multi = vfio_platform_hot_reset_multi,
    .vfio_check_device = vfio_platform_check_device,
    .vfio_get_device_regions = vfio_platform_get_device_regions,
    .vfio_get_device_interrupts = vfio_platform_get_device_interrupts,
};


static void vfio_platform_realize(DeviceState *dev, Error **errp)
{
    SysBusDevice *sbdev = SYS_BUS_DEVICE(dev);
    VFIOPlatformDevice *vdev = container_of(sbdev, VFIOPlatformDevice, sbdev);
    VFIODevice *vbasedev = &vdev->vdev;
    int i, ret;

    vbasedev->ops = &vfio_platform_ops;

    /* TODO: pass device name on command line */
    vbasedev->name = malloc(PATH_MAX);
    snprintf(vbasedev->name, PATH_MAX, "%s", "fff51000.ethernet");

    ret = vfio_base_device_init(vbasedev, VFIO_DEVICE_TYPE_PLATFORM);
    if (ret < 0) {
        return;
    }

    for (i = 0; i < vbasedev->num_regions; i++) {
        vfio_map_region(vdev, i);
        sysbus_init_mmio(sbdev, &vbasedev->regions[i]->mem);
    }
}

static void vfio_platform_unrealize(DeviceState *dev, Error **errp)
{
    int i;
    VFIOINTp *intp, *next_intp;
    SysBusDevice *sbdev = SYS_BUS_DEVICE(dev);
    VFIOPlatformDevice *vplatdev = container_of(sbdev,
                                                VFIOPlatformDevice, sbdev);
    VFIODevice *vbasedev = &vplatdev->vdev;
    VFIOGroup *group = vbasedev->group;
    /*
     * placeholder for
     * vfio_unregister_err_notifier(vdev)
     * vfio_disable_interrupts(vdev);
     * timer free
     * g_free vdev dynamic fields
    */
    vfio_disable_intp(vbasedev);

    while (!QSIMPLEQ_EMPTY(&vplatdev->pending_intp_queue)) {
            QSIMPLEQ_REMOVE_HEAD(&vplatdev->pending_intp_queue, pqnext);
     }

    QLIST_FOREACH_SAFE(intp, &vplatdev->intp_list, next, next_intp) {
        QLIST_REMOVE(intp, next);
        g_free(intp);
    }

    if (vbasedev->mmap_timer) {
        timer_free(vbasedev->mmap_timer);
    }

    vfio_unmap_regions(vbasedev);

    for (i = 0; i < vbasedev->num_regions; i++) {
        g_free(vbasedev->regions[i]);
    }
    g_free(vbasedev->regions);

    vfio_put_base_device(vbasedev);
    vfio_put_group(group, vfio_reset_handler);

}

static const VMStateDescription vfio_platform_vmstate = {
    .name = TYPE_VFIO_PLATFORM,
    .unmigratable = 1,
};

typedef struct VFIOPlatformDeviceClass {
    DeviceClass parent_class;

    int (*init)(VFIODevice *dev);
} VFIOPlatformDeviceClass;

#define VFIO_PLATFORM_DEVICE(obj) \
     OBJECT_CHECK(VFIOPlatformDevice, (obj), TYPE_VFIO_PLATFORM)
#define VFIO_PLATFORM_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(VFIOPlatformDeviceClass, (klass), TYPE_VFIO_PLATFORM)
#define VFIO_PLATFORM_DEVICE_GET_CLASS(obj) \
     OBJECT_GET_CLASS(VFIOPlatformDeviceClass, (obj), TYPE_VFIO_PLATFORM)



static void vfio_platform_dev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VFIOPlatformDeviceClass *vdc = VFIO_PLATFORM_DEVICE_CLASS(klass);

    dc->realize = vfio_platform_realize;
    dc->unrealize = vfio_platform_unrealize;
    dc->vmsd = &vfio_platform_vmstate;
    dc->desc = "VFIO-based platform device assignment";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    vdc->init = NULL;
}

static const TypeInfo vfio_platform_dev_info = {
    .name = TYPE_VFIO_PLATFORM,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VFIOPlatformDevice),
    .class_init = vfio_platform_dev_class_init,
    .class_size = sizeof(VFIOPlatformDeviceClass),
};

static void register_vfio_platform_dev_type(void)
{
    type_register_static(&vfio_platform_dev_info);
}

type_init(register_vfio_platform_dev_type)

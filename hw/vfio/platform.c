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


typedef struct VFIOPlatformDevice {
    SysBusDevice sbdev;
    VFIODevice vdev; /* not a QOM object */
/* interrupts to come later on */
} VFIOPlatformDevice;


static const MemoryRegionOps vfio_region_ops = {
    .read = vfio_region_read,
    .write = vfio_region_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

/*
 * It is mandatory to pass a VFIOPlatformDevice since VFIODevice
 * is not an Object and cannot be passed to memory region functions
*/

static void vfio_map_region(VFIOPlatformDevice *vdev, int nr)
{
    VFIORegion *region = vdev->vdev.regions[nr];
    unsigned size = region->size;
    char name[64];

    snprintf(name, sizeof(name), "VFIO %s region %d", vdev->vdev.name, nr);

    /* A "slow" read/write mapping underlies all regions  */
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


/* not implemented yet */
static int vfio_platform_get_device_interrupts(VFIODevice *vdev)
{
    return 0;
}

/* not implemented yet */
static void vfio_platform_eoi(VFIODevice *vdev)
{
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
    SysBusDevice *sbdev = SYS_BUS_DEVICE(dev);
    VFIOPlatformDevice *vdev = container_of(sbdev, VFIOPlatformDevice, sbdev);
    VFIODevice *vbasedev = &vdev->vdev;
    VFIOGroup *group = vbasedev->group;
    /*
     * placeholder for
     * vfio_unregister_err_notifier(vdev)
     * vfio_disable_interrupts(vdev);
     * timer free
     * g_free vdev dynamic fields
    */
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

/*
 * common header for vfio based device assignment support
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Alex Williamson <alex.williamson@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on qemu-kvm device-assignment:
 *  Adapted for KVM by Qumranet.
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 *  Copyright (C) 2008, IBM, Muli Ben-Yehuda (muli@il.ibm.com)
 */

#include "hw/hw.h"

/*#define DEBUG_VFIO*/
#ifdef DEBUG_VFIO
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "vfio: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

/* Extra debugging, trap acceleration paths for more logging */
#define VFIO_ALLOW_MMAP 1
#define VFIO_ALLOW_KVM_INTX 1
#define VFIO_ALLOW_KVM_MSI 1
#define VFIO_ALLOW_KVM_MSIX 1

#define TYPE_VFIO_PLATFORM "vfio-platform"

enum {
    VFIO_DEVICE_TYPE_PCI = 0,
    VFIO_DEVICE_TYPE_PLATFORM = 1,
};

enum {
    VFIO_IRQ_INACTIVE = 0,
    VFIO_IRQ_PENDING = 1,
    VFIO_IRQ_ACTIVE = 2,
    /* VFIO_IRQ_ACTIVE_AND_PENDING cannot happen with VFIO */
};

struct VFIOGroup;
struct VFIODevice;

typedef struct VFIODeviceOps VFIODeviceOps;

/* Base Class for a VFIO Region */

typedef struct VFIORegion {
    struct VFIODevice *vdev;
    off_t fd_offset; /* offset of region within device fd */
    int fd; /* device fd, allows us to pass VFIORegion as opaque data */
    MemoryRegion mem; /* slow, read/write access */
    MemoryRegion mmap_mem; /* direct mapped access */
    void *mmap;
    size_t size;
    uint32_t flags; /* VFIO region flags (rd/wr/mmap) */
    uint8_t nr; /* cache the region number for debug */
} VFIORegion;

/* Base Class for a VFIO device */

typedef struct VFIODevice {
    QLIST_ENTRY(VFIODevice) next;
    struct VFIOGroup *group;
    unsigned int num_regions;
    VFIORegion **regions;
    unsigned int num_irqs;
    char *name;
    int fd;
    int type;
    bool reset_works;
    bool needs_reset;
    uint32_t mmap_timeout; /* delay to re-enable mmaps after interrupt */
    QEMUTimer *mmap_timer; /* enable mmaps after periods w/o interrupts */
    VFIODeviceOps *ops;
} VFIODevice;


typedef struct VFIOType1 {
    MemoryListener listener;
    int error;
    bool initialized;
} VFIOType1;

typedef struct VFIOContainer {
    int fd; /* /dev/vfio/vfio, empowered by the attached groups */
    struct {
        /* enable abstraction to support various iommu backends */
        union {
            VFIOType1 type1;
        };
        void (*release)(struct VFIOContainer *);
    } iommu_data;
    QLIST_HEAD(, VFIOGroup) group_list;
    QLIST_ENTRY(VFIOContainer) next;
} VFIOContainer;

typedef struct VFIOGroup {
    int fd;
    int groupid;
    VFIOContainer *container;
    QLIST_HEAD(, VFIODevice) device_list;
    QLIST_ENTRY(VFIOGroup) next;
    QLIST_ENTRY(VFIOGroup) container_next;
} VFIOGroup;


struct VFIODeviceOps {
    bool (*vfio_compute_needs_reset)(VFIODevice *vdev);
    int (*vfio_hot_reset_multi)(VFIODevice *vdev);
    void (*vfio_eoi)(VFIODevice *vdev);
    int (*vfio_check_device)(VFIODevice *vdev);
    int (*vfio_get_device_regions)(VFIODevice *vdev);
    int (*vfio_get_device_interrupts)(VFIODevice *vdev);
};



VFIOGroup *vfio_get_group(int groupid, QEMUResetHandler *reset_handler);
void vfio_put_group(VFIOGroup *group, QEMUResetHandler *reset_handler);

void vfio_reset_handler(void *opaque);

void vfio_unmask_irqindex(VFIODevice *vdev, int index);
void vfio_disable_irqindex(VFIODevice *vdev, int index);
void vfio_mask_int(VFIODevice *vdev, int index);

void vfio_region_write(void *opaque, hwaddr addr, uint64_t data, unsigned size);
uint64_t vfio_region_read(void *opaque, hwaddr addr, unsigned size);

int vfio_get_base_device(VFIOGroup *group, const char *name,
                        struct VFIODevice *vdev);
void vfio_put_base_device(VFIODevice *vdev);
int vfio_base_device_init(VFIODevice *vdev, int type);
void print_regions(VFIODevice *vdev);

int vfio_mmap_region(Object *vdev, VFIORegion *region,
                     MemoryRegion *mem, MemoryRegion *submem,
                     void **map, size_t size, off_t offset,
                     const char *name);

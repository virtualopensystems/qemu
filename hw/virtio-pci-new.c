/*
 * Virtio PCI Bindings
 *
 * Copyright IBM, Corp. 2007
 * Copyright (c) 2009 CodeSourcery
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Paul Brook        <paul@codesourcery.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <inttypes.h>

#include "virtio.h"
#include "virtio-transport.h"
#include "virtio-blk.h"
#include "virtio-net.h"
#include "virtio-serial.h"
#include "virtio-scsi.h"
#include "virtio-balloon.h"
#include "pci.h"
#include "qemu-error.h"
#include "msi.h"
#include "msix.h"
#include "net.h"
#include "loader.h"
#include "kvm.h"
#include "blockdev.h"
#include "virtio-pci.h"
#include "range.h"

/* from Linux's linux/virtio_pci.h */

/* A 32-bit r/o bitmask of the features supported by the host */
#define VIRTIO_PCI_HOST_FEATURES        0

/* A 32-bit r/w bitmask of features activated by the guest */
#define VIRTIO_PCI_GUEST_FEATURES       4

/* A 32-bit r/w PFN for the currently selected queue */
#define VIRTIO_PCI_QUEUE_PFN            8

/* A 16-bit r/o queue size for the currently selected queue */
#define VIRTIO_PCI_QUEUE_NUM            12

/* A 16-bit r/w queue selector */
#define VIRTIO_PCI_QUEUE_SEL            14

/* A 16-bit r/w queue notifier */
#define VIRTIO_PCI_QUEUE_NOTIFY         16

/* An 8-bit device status register.  */
#define VIRTIO_PCI_STATUS               18

/* An 8-bit r/o interrupt status register.  Reading the value will return the
 * current contents of the ISR and will also clear it.  This is effectively
 * a read-and-acknowledge. */
#define VIRTIO_PCI_ISR                  19

/* MSI-X registers: only enabled if MSI-X is enabled. */
/* A 16-bit vector for configuration changes. */
#define VIRTIO_MSI_CONFIG_VECTOR        20
/* A 16-bit vector for selected queue notifications. */
#define VIRTIO_MSI_QUEUE_VECTOR         22

/* Config space size */
#define VIRTIO_PCI_CONFIG_NOMSI         20
#define VIRTIO_PCI_CONFIG_MSI           24
#define VIRTIO_PCI_REGION_SIZE(dev)     (msix_present(dev) ? \
                                         VIRTIO_PCI_CONFIG_MSI : \
                                         VIRTIO_PCI_CONFIG_NOMSI)

/* The remaining space is defined by each driver as the per-driver
 * configuration space */
#define VIRTIO_PCI_CONFIG(dev)          (msix_enabled(dev) ? \
                                         VIRTIO_PCI_CONFIG_MSI : \
                                         VIRTIO_PCI_CONFIG_NOMSI)

/* How many bits to shift physical queue address written to QUEUE_PFN.
 * 12 is historical, and due to x86 page size. */
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT    12

/* Flags track per-device state like workarounds for quirks in older guests. */
#define VIRTIO_PCI_FLAG_BUS_MASTER_BUG  (1 << 0)

/* QEMU doesn't strictly need write barriers since everything runs in
 * lock-step.  We'll leave the calls to wmb() in though to make it obvious for
 * KVM or if kqemu gets SMP support.
 */
#define wmb() do { } while (0)

/* HACK for virtio to determine if it's running a big endian guest */
bool virtio_is_big_endian(void);

/* virtio device */

static void virtio_pci_notify(void *opaque, uint16_t vector)
{
    VirtIOPCI *s = opaque;
    if (msix_enabled(&s->pci_dev)) {
        msix_notify(&s->pci_dev, vector);
    }
    else {
        qemu_set_irq(s->pci_dev.irq[0], s->vdev->isr & 1);
    }
}

static void virtio_pci_save_config(void * opaque, QEMUFile *f)
{
    VirtIOPCI *s = opaque;
    pci_device_save(&s->pci_dev, f);
    msix_save(&s->pci_dev, f);
    if (msix_present(&s->pci_dev)) {
        qemu_put_be16(f, s->vdev->config_vector);
    }
}

static void virtio_pci_save_queue(void * opaque, int n, QEMUFile *f)
{
    VirtIOPCI *s = opaque;
    if (msix_present(&s->pci_dev)) {
        qemu_put_be16(f, virtio_queue_vector(s->vdev, n));
    }
}

static int virtio_pci_load_config(void * opaque, QEMUFile *f)
{
    VirtIOPCI *s = opaque;
    int ret;
    ret = pci_device_load(&s->pci_dev, f);
    if (ret) {
        return ret;
    }
    msix_unuse_all_vectors(&s->pci_dev);
    msix_load(&s->pci_dev, f);
    if (msix_present(&s->pci_dev)) {
        qemu_get_be16s(f, &s->vdev->config_vector);
    } else {
        s->vdev->config_vector = VIRTIO_NO_VECTOR;
    }
    if (s->vdev->config_vector != VIRTIO_NO_VECTOR) {
        return msix_vector_use(&s->pci_dev, s->vdev->config_vector);
    }
    return 0;
}

static int virtio_pci_load_queue(void * opaque, int n, QEMUFile *f)
{
    VirtIOPCI *s = opaque;
    uint16_t vector;
    if (msix_present(&s->pci_dev)) {
        qemu_get_be16s(f, &vector);
    } else {
        vector = VIRTIO_NO_VECTOR;
    }
    virtio_queue_set_vector(s->vdev, n, vector);
    if (vector != VIRTIO_NO_VECTOR) {
        return msix_vector_use(&s->pci_dev, vector);
    }
    return 0;
}

static int virtio_pci_set_host_notifier_internal(VirtIOPCI *s, int n,
        bool assign, bool set_handler)
{
    VirtQueue *vq = virtio_get_queue(s->vdev, n);
    EventNotifier *notifier = virtio_queue_get_host_notifier(vq);
    int r = 0;

    if (assign) {
        r = event_notifier_init(notifier, 1);
        if (r < 0) {
            error_report("%s: unable to init event notifier: %d", __func__, r);
            return r;
        }
        virtio_queue_set_host_notifier_fd_handler(vq, true, set_handler);
        memory_region_add_eventfd(&s->bar, VIRTIO_PCI_QUEUE_NOTIFY, 2, true, n,
                notifier);
    } else {
        memory_region_del_eventfd(&s->bar, VIRTIO_PCI_QUEUE_NOTIFY, 2, true, n,
                notifier);
        virtio_queue_set_host_notifier_fd_handler(vq, false, false);
        event_notifier_cleanup(notifier);
    }
    return r;
}

static void virtio_pci_start_ioeventfd(VirtIOPCI *s)
{
    int n, r;

    if (!(s->flags & VIRTIO_PCI_FLAG_USE_IOEVENTFD) ||
        s->ioeventfd_disabled ||
        s->ioeventfd_started) {
        return;
    }

    for (n = 0; n < VIRTIO_PCI_QUEUE_MAX; n++) {
        if (!virtio_queue_get_num(s->vdev, n)) {
            continue;
        }

        r = virtio_pci_set_host_notifier_internal(s, n, true, true);
        if (r < 0) {
            goto assign_error;
        }
    }
    s->ioeventfd_started = true;
    return;

assign_error:
    while (--n >= 0) {
        if (!virtio_queue_get_num(s->vdev, n)) {
            continue;
        }

        r = virtio_pci_set_host_notifier_internal(s, n, false, false);
        assert(r >= 0);
    }
    s->ioeventfd_started = false;
    error_report("%s: failed. Fallback to a userspace (slower).", __func__);
}

static void virtio_pci_stop_ioeventfd(VirtIOPCI *s)
{
    int r;
    int n;

    if (!s->ioeventfd_started) {
        return;
    }

    for (n = 0; n < VIRTIO_PCI_QUEUE_MAX; n++) {
        if (!virtio_queue_get_num(s->vdev, n)) {
            continue;
        }

        r = virtio_pci_set_host_notifier_internal(s, n, false, false);
        assert(r >= 0);
    }
    s->ioeventfd_started = false;
}

void virtio_pci_reset_(DeviceState *d)
{
    VirtIOPCI *s =
            container_of(d, VirtIOPCI, pci_dev.qdev);
    virtio_pci_stop_ioeventfd(s);
    if (s->vdev) {
        virtio_reset(s->vdev);
    }
    msix_unuse_all_vectors(&s->pci_dev);
    s->flags &= ~VIRTIO_PCI_FLAG_BUS_MASTER_BUG;
}

static void virtio_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    VirtIOPCI *s = opaque;
    VirtIODevice *vdev = s->vdev;
    target_phys_addr_t pa;

    switch (addr) {
    case VIRTIO_PCI_GUEST_FEATURES:
	/* Guest does not negotiate properly?  We have to assume nothing. */
	if (val & (1 << VIRTIO_F_BAD_FEATURE)) {
            val = vdev->bad_features ? vdev->bad_features(vdev) : 0;
	}
        virtio_set_features(vdev, val);
        break;
    case VIRTIO_PCI_QUEUE_PFN:
        pa = (target_phys_addr_t)val << VIRTIO_PCI_QUEUE_ADDR_SHIFT;
        if (pa == 0) {
            virtio_pci_stop_ioeventfd(s);
            virtio_reset(s->vdev);
            msix_unuse_all_vectors(&s->pci_dev);
        }
        else
            virtio_queue_set_addr(vdev, vdev->queue_sel, pa);
        break;
    case VIRTIO_PCI_QUEUE_SEL:
        if (val < VIRTIO_PCI_QUEUE_MAX)
            vdev->queue_sel = val;
        break;
    case VIRTIO_PCI_QUEUE_NOTIFY:
        if (val < VIRTIO_PCI_QUEUE_MAX) {
            virtio_queue_notify(vdev, val);
        }
        break;
    case VIRTIO_PCI_STATUS:
        if (!(val & VIRTIO_CONFIG_S_DRIVER_OK)) {
            virtio_pci_stop_ioeventfd(s);
        }

        virtio_set_status(vdev, val & 0xFF);

        if (val & VIRTIO_CONFIG_S_DRIVER_OK) {
            virtio_pci_start_ioeventfd(s);
        }

        if (vdev->status == 0) {
            virtio_reset(s->vdev);
            msix_unuse_all_vectors(&s->pci_dev);
        }

        /* Linux before 2.6.34 sets the device as OK without enabling
           the PCI device bus master bit. In this case we need to disable
           some safety checks. */
        if ((val & VIRTIO_CONFIG_S_DRIVER_OK) &&
            !(s->pci_dev.config[PCI_COMMAND] & PCI_COMMAND_MASTER)) {
            s->flags |= VIRTIO_PCI_FLAG_BUS_MASTER_BUG;
        }
        break;
    case VIRTIO_MSI_CONFIG_VECTOR:
        msix_vector_unuse(&s->pci_dev, vdev->config_vector);
        /* Make it possible for guest to discover an error took place. */
        if (msix_vector_use(&s->pci_dev, val) < 0)
            val = VIRTIO_NO_VECTOR;
        vdev->config_vector = val;
        break;
    case VIRTIO_MSI_QUEUE_VECTOR:
        msix_vector_unuse(&s->pci_dev,
                          virtio_queue_vector(vdev, vdev->queue_sel));
        /* Make it possible for guest to discover an error took place. */
        if (msix_vector_use(&s->pci_dev, val) < 0)
            val = VIRTIO_NO_VECTOR;
        virtio_queue_set_vector(vdev, vdev->queue_sel, val);
        break;
    default:
        error_report("%s: unexpected address 0x%x value 0x%x",
                     __func__, addr, val);
        break;
    }
}

static uint32_t virtio_ioport_read(VirtIOPCI *s, uint32_t addr)
{
    VirtIODevice *vdev = s->vdev;
    uint32_t ret = 0xFFFFFFFF;

    switch (addr) {
    case VIRTIO_PCI_HOST_FEATURES:
        ret = s->host_features;
        break;
    case VIRTIO_PCI_GUEST_FEATURES:
        ret = vdev->guest_features;
        break;
    case VIRTIO_PCI_QUEUE_PFN:
        ret = virtio_queue_get_addr(vdev, vdev->queue_sel)
              >> VIRTIO_PCI_QUEUE_ADDR_SHIFT;
        break;
    case VIRTIO_PCI_QUEUE_NUM:
        ret = virtio_queue_get_num(vdev, vdev->queue_sel);
        break;
    case VIRTIO_PCI_QUEUE_SEL:
        ret = vdev->queue_sel;
        break;
    case VIRTIO_PCI_STATUS:
        ret = vdev->status;
        break;
    case VIRTIO_PCI_ISR:
        /* reading from the ISR also clears it. */
        ret = vdev->isr;
        vdev->isr = 0;
        qemu_set_irq(s->pci_dev.irq[0], 0);
        break;
    case VIRTIO_MSI_CONFIG_VECTOR:
        ret = vdev->config_vector;
        break;
    case VIRTIO_MSI_QUEUE_VECTOR:
        ret = virtio_queue_vector(vdev, vdev->queue_sel);
        break;
    default:
        break;
    }

    return ret;
}

static uint32_t virtio_pci_config_readb(void *opaque, uint32_t addr)
{
    VirtIOPCI *s = opaque;
    uint32_t config = VIRTIO_PCI_CONFIG(&s->pci_dev);
    if (addr < config)
        return virtio_ioport_read(s, addr);
    addr -= config;
    return virtio_config_readb(s->vdev, addr);
}

static uint32_t virtio_pci_config_readw(void *opaque, uint32_t addr)
{
    VirtIOPCI *s = opaque;
    uint32_t config = VIRTIO_PCI_CONFIG(&s->pci_dev);
    uint16_t val;
    if (addr < config)
        return virtio_ioport_read(s, addr);
    addr -= config;
    val = virtio_config_readw(s->vdev, addr);
    if (virtio_is_big_endian()) {
        /*
         * virtio is odd, ioports are LE but config space is target native
         * endian. However, in qemu, all PIO is LE, so we need to re-swap
         * on BE targets
         */
        val = bswap16(val);
    }
    return val;
}

static uint32_t virtio_pci_config_readl(void *opaque, uint32_t addr)
{
    VirtIOPCI *s = opaque;
    uint32_t config = VIRTIO_PCI_CONFIG(&s->pci_dev);
    uint32_t val;
    if (addr < config)
        return virtio_ioport_read(s, addr);
    addr -= config;
    val = virtio_config_readl(s->vdev, addr);
    if (virtio_is_big_endian()) {
        val = bswap32(val);
    }
    return val;
}

static void virtio_pci_config_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    VirtIOPCI *s = opaque;
    uint32_t config = VIRTIO_PCI_CONFIG(&s->pci_dev);
    if (addr < config) {
        virtio_ioport_write(s, addr, val);
        return;
    }
    addr -= config;
    virtio_config_writeb(s->vdev, addr, val);
}

static void virtio_pci_config_writew(void *opaque, uint32_t addr, uint32_t val)
{
    VirtIOPCI *s = opaque;
    uint32_t config = VIRTIO_PCI_CONFIG(&s->pci_dev);
    if (addr < config) {
        virtio_ioport_write(s, addr, val);
        return;
    }
    addr -= config;
    if (virtio_is_big_endian()) {
        val = bswap16(val);
    }
    virtio_config_writew(s->vdev, addr, val);
}

static void virtio_pci_config_writel(void *opaque, uint32_t addr, uint32_t val)
{
    VirtIOPCI *s = opaque;
    uint32_t config = VIRTIO_PCI_CONFIG(&s->pci_dev);
    if (addr < config) {
        virtio_ioport_write(s, addr, val);
        return;
    }
    addr -= config;
    if (virtio_is_big_endian()) {
        val = bswap32(val);
    }
    virtio_config_writel(s->vdev, addr, val);
}

static const MemoryRegionPortio virtio_portio[] = {
    { 0, 0x10000, 1, .write = virtio_pci_config_writeb, },
    { 0, 0x10000, 2, .write = virtio_pci_config_writew, },
    { 0, 0x10000, 4, .write = virtio_pci_config_writel, },
    { 0, 0x10000, 1, .read = virtio_pci_config_readb, },
    { 0, 0x10000, 2, .read = virtio_pci_config_readw, },
    { 0, 0x10000, 4, .read = virtio_pci_config_readl, },
    PORTIO_END_OF_LIST()
};

static const MemoryRegionOps virtio_pci_config_ops = {
    .old_portio = virtio_portio,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void virtio_write_config(PCIDevice *pci_dev, uint32_t address,
                                uint32_t val, int len)
{
    VirtIOPCI *s = DO_UPCAST(VirtIOPCI,
            pci_dev, pci_dev);

    pci_default_write_config(pci_dev, address, val, len);

    if (range_covers_byte(address, len, PCI_COMMAND) &&
        !(pci_dev->config[PCI_COMMAND] & PCI_COMMAND_MASTER) &&
        !(s->flags & VIRTIO_PCI_FLAG_BUS_MASTER_BUG)) {
        virtio_pci_stop_ioeventfd(s);
        virtio_set_status(s->vdev,
                          s->vdev->status & ~VIRTIO_CONFIG_S_DRIVER_OK);
    }
}

static unsigned virtio_pci_get_features(void *opaque)
{
    VirtIOPCI *s = opaque;
    return s->host_features;
}

static int kvm_virtio_pci_vq_vector_use(VirtIOPCI *s,
                                        unsigned int queue_no,
                                        unsigned int vector,
                                        MSIMessage msg)
{
    VirtQueue *vq = virtio_get_queue(s->vdev, queue_no);
    EventNotifier *n = virtio_queue_get_guest_notifier(vq);
    VirtIOIRQFD *irqfd = &s->vector_irqfd[vector];
    int ret;

    if (irqfd->users == 0) {
        ret = kvm_irqchip_add_msi_route(kvm_state, msg);
        if (ret < 0) {
            return ret;
        }
        irqfd->virq = ret;
    }
    irqfd->users++;

    ret = kvm_irqchip_add_irq_notifier(kvm_state, n, irqfd->virq);
    if (ret < 0) {
        if (--irqfd->users == 0) {
            kvm_irqchip_release_virq(kvm_state, irqfd->virq);
        }
        return ret;
    }

    virtio_queue_set_guest_notifier_fd_handler(vq, true, true);
    return 0;
}

static void kvm_virtio_pci_vq_vector_release(VirtIOPCI *s,
                                             unsigned int queue_no,
                                             unsigned int vector)
{
    VirtQueue *vq = virtio_get_queue(s->vdev, queue_no);
    EventNotifier *n = virtio_queue_get_guest_notifier(vq);
    VirtIOIRQFD *irqfd = &s->vector_irqfd[vector];
    int ret;

    ret = kvm_irqchip_remove_irq_notifier(kvm_state, n, irqfd->virq);
    assert(ret == 0);

    if (--irqfd->users == 0) {
        kvm_irqchip_release_virq(kvm_state, irqfd->virq);
    }

    virtio_queue_set_guest_notifier_fd_handler(vq, true, false);
}

static int kvm_virtio_pci_vector_use(PCIDevice *dev, unsigned vector,
                                     MSIMessage msg)
{
    VirtIOPCI *s = container_of(dev, VirtIOPCI, pci_dev);
    VirtIODevice *vdev = s->vdev;
    int ret, queue_no;

    for (queue_no = 0; queue_no < VIRTIO_PCI_QUEUE_MAX; queue_no++) {
        if (!virtio_queue_get_num(vdev, queue_no)) {
            break;
        }
        if (virtio_queue_vector(vdev, queue_no) != vector) {
            continue;
        }
        ret = kvm_virtio_pci_vq_vector_use(s, queue_no, vector, msg);
        if (ret < 0) {
            goto undo;
        }
    }
    return 0;

undo:
    while (--queue_no >= 0) {
        if (virtio_queue_vector(vdev, queue_no) != vector) {
            continue;
        }
        kvm_virtio_pci_vq_vector_release(s, queue_no, vector);
    }
    return ret;
}

static void kvm_virtio_pci_vector_release(PCIDevice *dev, unsigned vector)
{
    VirtIOPCI *s = container_of(dev, VirtIOPCI, pci_dev);
    VirtIODevice *vdev = s->vdev;
    int queue_no;

    for (queue_no = 0; queue_no < VIRTIO_PCI_QUEUE_MAX; queue_no++) {
        if (!virtio_queue_get_num(vdev, queue_no)) {
            break;
        }
        if (virtio_queue_vector(vdev, queue_no) != vector) {
            continue;
        }
        kvm_virtio_pci_vq_vector_release(s, queue_no, vector);
    }
}

static int virtio_pci_set_guest_notifier(void *opaque, int n, bool assign)
{
    VirtIOPCI *s = opaque;
    VirtQueue *vq = virtio_get_queue(s->vdev, n);
    EventNotifier *notifier = virtio_queue_get_guest_notifier(vq);

    if (assign) {
        int r = event_notifier_init(notifier, 0);
        if (r < 0) {
            return r;
        }
        virtio_queue_set_guest_notifier_fd_handler(vq, true, false);
    } else {
        virtio_queue_set_guest_notifier_fd_handler(vq, false, false);
        event_notifier_cleanup(notifier);
    }

    return 0;
}

static bool virtio_pci_query_guest_notifiers(void *opaque)
{
    VirtIOPCI *s = opaque;
    return msix_enabled(&s->pci_dev);
}

static int virtio_pci_set_guest_notifiers(void *opaque, bool assign)
{
    VirtIOPCI *s = opaque;
    VirtIODevice *vdev = s->vdev;
    int r, n;

    /* Must unset vector notifier while guest notifier is still assigned */
    if (kvm_msi_via_irqfd_enabled() && !assign) {
        msix_unset_vector_notifiers(&s->pci_dev);
        g_free(s->vector_irqfd);
        s->vector_irqfd = NULL;
    }

    for (n = 0; n < VIRTIO_PCI_QUEUE_MAX; n++) {
        if (!virtio_queue_get_num(vdev, n)) {
            break;
        }

        r = virtio_pci_set_guest_notifier(opaque, n, assign);
        if (r < 0) {
            goto assign_error;
        }
    }

    /* Must set vector notifier after guest notifier has been assigned */
    if (kvm_msi_via_irqfd_enabled() && assign) {
        s->vector_irqfd =
            g_malloc0(sizeof(*s->vector_irqfd) *
                      msix_nr_vectors_allocated(&s->pci_dev));
        r = msix_set_vector_notifiers(&s->pci_dev,
                                      kvm_virtio_pci_vector_use,
                                      kvm_virtio_pci_vector_release);
        if (r < 0) {
            goto assign_error;
        }
    }

    return 0;

assign_error:
    /* We get here on assignment failure. Recover by undoing for VQs 0 .. n. */
    assert(assign);
    while (--n >= 0) {
        virtio_pci_set_guest_notifier(opaque, n, !assign);
    }
    return r;
}

static int virtio_pci_set_host_notifier(void *opaque, int n, bool assign)
{
    VirtIOPCI *s = opaque;

    /* Stop using ioeventfd for virtqueue kick if the device starts using host
     * notifiers.  This makes it easy to avoid stepping on each others' toes.
     */
    s->ioeventfd_disabled = assign;
    if (assign) {
        virtio_pci_stop_ioeventfd(s);
    }
    /* We don't need to start here: it's not needed because backend
     * currently only stops on status change away from ok,
     * reset, vmstop and such. If we do add code to start here,
     * need to check vmstate, device state etc. */
    return virtio_pci_set_host_notifier_internal(s, n, assign, false);
}

static void virtio_pci_vmstate_change(void *opaque, bool running)
{
    VirtIOPCI *s = opaque;

    if (running) {
        /* Try to find out if the guest has bus master disabled, but is
           in ready state. Then we have a buggy guest OS. */
        if ((s->vdev->status & VIRTIO_CONFIG_S_DRIVER_OK) &&
            !(s->pci_dev.config[PCI_COMMAND] & PCI_COMMAND_MASTER)) {
            s->flags |= VIRTIO_PCI_FLAG_BUS_MASTER_BUG;
        }
        virtio_pci_start_ioeventfd(s);
    } else {
        virtio_pci_stop_ioeventfd(s);
    }
}

static const VirtIOBindings virtio_pci_bindings = {
    .notify = virtio_pci_notify,
    .save_config = virtio_pci_save_config,
    .load_config = virtio_pci_load_config,
    .save_queue = virtio_pci_save_queue,
    .load_queue = virtio_pci_load_queue,
    .get_features = virtio_pci_get_features,
    .query_guest_notifiers = virtio_pci_query_guest_notifiers,
    .set_host_notifier = virtio_pci_set_host_notifier,
    .set_guest_notifiers = virtio_pci_set_guest_notifiers,
    .vmstate_change = virtio_pci_vmstate_change,
};

static void virtio_init_pci_(VirtIOPCI *s, VirtIODevice *vdev)
{
    uint8_t *config;
    uint32_t size;

    s->vdev = vdev;

    config = s->pci_dev.config;

    if (s->class_code) {
        pci_config_set_class(config, s->class_code);
    }
    pci_set_word(config + PCI_SUBSYSTEM_VENDOR_ID,
                 pci_get_word(config + PCI_VENDOR_ID));
    pci_set_word(config + PCI_SUBSYSTEM_ID, vdev->device_id);
    config[PCI_INTERRUPT_PIN] = 1;

    if (vdev->nvectors &&
        msix_init_exclusive_bar(&s->pci_dev, vdev->nvectors, 1)) {
        vdev->nvectors = 0;
    }

    s->pci_dev.config_write = virtio_write_config;

    size = VIRTIO_PCI_REGION_SIZE(&s->pci_dev) + vdev->config_len;
    if (size & (size-1))
        size = 1 << qemu_fls(size);

    memory_region_init_io(&s->bar, &virtio_pci_config_ops, s,
                          "virtio-pci", size);
    pci_register_bar(&s->pci_dev, 0, PCI_BASE_ADDRESS_SPACE_IO,
                     &s->bar);

    if (!kvm_has_many_ioeventfds()) {
        s->flags &= ~VIRTIO_PCI_FLAG_USE_IOEVENTFD;
    }

    virtio_bind_device(vdev, &virtio_pci_bindings, s);
    s->host_features |= 0x1 << VIRTIO_F_NOTIFY_ON_EMPTY;
    s->host_features |= 0x1 << VIRTIO_F_BAD_FEATURE;
    s->host_features = vdev->get_features(vdev, s->host_features);
}

static void virtio_exit_pci(PCIDevice *pci_dev)
{
    VirtIOPCI *s = DO_UPCAST(VirtIOPCI, pci_dev, pci_dev);

    memory_region_destroy(&s->bar);
    msix_uninit_exclusive_bar(pci_dev);
}

static int virtio_pci_transport_cb(DeviceState *dev, VirtIODevice *vdev,
        VirtIOTransportLink *trl)
{
    PCIDevice *pci_dev = DO_UPCAST(PCIDevice, qdev, trl->tr);
    VirtIOPCI *s = DO_UPCAST(VirtIOPCI, pci_dev, pci_dev);

    virtio_plug_into_transport(dev, trl);

    // TODO: Figure out if props were explicitly set before

    /* Get default host_features passed from back-end */
    s->host_features = s->trl->host_features;

    switch (vdev->device_id) {
    case VIRTIO_ID_BLOCK:
        s->flags |= VIRTIO_PCI_FLAG_USE_IOEVENTFD;
        s->nvectors = 2;

        if (s->class_code != PCI_CLASS_STORAGE_SCSI &&
            s->class_code != PCI_CLASS_STORAGE_OTHER) {
            s->class_code = PCI_CLASS_STORAGE_SCSI;
        }

        vdev->nvectors = s->nvectors;
        pci_config_set_device_id(s->pci_dev.config, PCI_DEVICE_ID_VIRTIO_BLOCK);
        pci_config_set_class(s->pci_dev.config, PCI_CLASS_STORAGE_SCSI);
        virtio_init_pci_(s, vdev);
        s->nvectors = vdev->nvectors;
        break;
    case VIRTIO_ID_NET:
        s->nvectors = 3;

        /* load rom */
        pci_dev->romfile = g_strdup("pxe-virtio.rom");
        pci_add_option_rom(pci_dev, false);

        vdev->nvectors = s->nvectors;
        pci_config_set_device_id(s->pci_dev.config, PCI_DEVICE_ID_VIRTIO_NET);
        pci_config_set_class(s->pci_dev.config, PCI_CLASS_NETWORK_ETHERNET);
        virtio_init_pci_(s, vdev);
        s->nvectors = vdev->nvectors;
        break;
    case VIRTIO_ID_BALLOON:
        break;
    case VIRTIO_ID_SCSI:
        break;
    case VIRTIO_ID_CONSOLE:
    {
        break;
    }
    default:
        fprintf(stderr,
                "Unknown back-end device id: 0x%" PRIx16 "\n", vdev->device_id);
        return -1;
    }

    return 0;
}

static int virtio_pci_device_init(PCIDevice *pci_dev)
{
    VirtIOPCI *s =
            DO_UPCAST(VirtIOPCI, pci_dev, pci_dev);

    virtio_init_transport(&pci_dev->qdev, &s->trl, VIRTIO_PCI,
            virtio_pci_transport_cb);

    return 0;
}

static void virtio_pci_device_exit(PCIDevice *pci_dev)
{
    VirtIOPCI *s =
            DO_UPCAST(VirtIOPCI, pci_dev, pci_dev);

    switch (s->vdev->device_id) {
        case VIRTIO_ID_BLOCK:
            virtio_pci_stop_ioeventfd(s);
            virtio_blk_exit(s->vdev);
            break;
        case VIRTIO_ID_NET:
            virtio_pci_stop_ioeventfd(s);
            virtio_net_exit(s->vdev);
            break;
        case VIRTIO_ID_BALLOON:
            virtio_pci_stop_ioeventfd(s);
            virtio_balloon_exit(s->vdev);
            break;
        case VIRTIO_ID_SCSI:
            virtio_scsi_exit(s->vdev);
            break;
        case VIRTIO_ID_CONSOLE:
            virtio_pci_stop_ioeventfd(s);
            virtio_serial_exit(s->vdev);
            break;
        default:
            fprintf(stderr,
                    "Unknown back-end device id: 0x%" PRIx16 "\n",
                    s->vdev->device_id);
            return;
        }

    virtio_exit_pci(pci_dev);

    return;
}

/******************** VirtIOPCI Device **********************/

static Property virtio_pci_properties[] = {
    DEFINE_PROP_HEX32("class", VirtIOPCI, class_code, 0),
    DEFINE_PROP_BIT("ioeventfd", VirtIOPCI, flags,
            VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, false),
    DEFINE_PROP_UINT32("vectors", VirtIOPCI, nvectors, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    k->init = virtio_pci_device_init;
    k->exit = virtio_pci_device_exit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    k->revision = VIRTIO_PCI_ABI_VERSION;
    k->class_id = PCI_CLASS_OTHERS;
    dc->reset = virtio_pci_reset_;
    dc->props = virtio_pci_properties;
}

static TypeInfo virtio_pci_info = {
    .name = VIRTIO_PCI,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(VirtIOPCI),
    .class_init = virtio_pci_class_init,
};

/************************************************************/

static void virtio_pci_register_types(void)
{
    type_register_static(&virtio_pci_info);
}

type_init(virtio_pci_register_types)

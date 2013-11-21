/*
 * Inter-VM Shared Memory Platform device (Nagianni).
 *
 * Authors:
 *      Alvise Rigo, Copyright (c) 2013 Virtual Open Systems
 *      Mian M. Hamayun, Copyright (c) 2013 Virtual Open Systems
 *
 * Based on: ivshmem.c
 *          Copyright (c) Cam Macdonell <cam@cs.ualberta.ca>
 *
 *      cirrus_vga.c
 *          Copyright (c) 2004 Fabrice Bellard
 *          Copyright (c) 2004 Makoto Suzuki (suzu)
 *
 *      and rtl8139.c
 *          Copyright (c) 2006 Igor Kovalenko
 *
 * This code is licensed under the GNU GPL v2.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "hw/sysbus.h"
#include "hw/devices.h"
#include "hw/arm/arm.h"
#include "sysemu/sysemu.h"
#include "sysemu/char.h"
#include <sys/types.h>
#include <sys/mman.h>

#define VENDOR_ID_NAGIANNI PCI_VENDOR_ID_REDHAT_QUMRANET

#define DEBUG_NAGIANNI
#ifdef DEBUG_NAGIANNI
#define NAGIANNI_DPRINTF(fmt, ...)  \
    do {printf("NAGIANNI: " fmt, ## __VA_ARGS__); } while (0)
#else
    #define NAGIANNI_DPRINTF(fmt, ...)
#endif

/*
 *
 * TODO
 * VMStateDescription vmstate_nagianni
 *
 **/

#define TYPE_NAGIANNI "nagianni"
#define NAGIANNI(obj) \
    OBJECT_CHECK(NagianniState, (obj), TYPE_NAGIANNI)

/*
 * TODO
 * Remove the following hard-coded values
 **/
#define REGISTER_MEM_SIZE   0x0100
#define SHARED_MEM_OFFSET   0x2000
#define SHARED_MEM_SIZE     0x8000

/* configuration register offsets */
enum nagianni_registers {
    INTRMASK = 0x0,
    INTRSTATUS = 0x04,
    IVPOSITION = 0x08,
    DOORBELL = 0x0C,
};

/*test eventfd trigger*/
#define EVENTFD_PROC_1  0x10

typedef struct NagianniState {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/

    uint64_t shm_size;  /* shared memory size in bytes */
    int shm_fd;         /* shared memory file descriptor */
    char * shmobj;      /* shared memory object name */
    void * shmem_ptr;   /* shared memory pointer */

    MemoryRegion mmio;  /* config regs description as mmio */
    MemoryRegion bar;   /* shared memory container region */
    MemoryRegion shm;   /* shared memory region description */

    /* irq */
    qemu_irq irq;
    uint32_t intrstatus;
    uint32_t intrmask;
    int vm_id;
    uint32_t doorbell;

    /* eventfd config register */
    int eventfd_fd;
    CharDriverState *peer_chrdev;
    CharDriverState *peer_eventfd_chrdev;
    EventNotifier   *peer_eventfd;
} NagianniState;

/*
 * methods declarations
 * */
static void nagianni_setup_peer(NagianniState *state);
static void peer_read(void *opaque, const uint8_t *buf, int size);
static void peer_event(void *opaque, int event);
static int  peer_canRead(void *opaque);
static void peer_eventfd_read(void *opaque, const uint8_t * buf, int size);
static int  peer_eventfd_canRead(void *opaque);
static void peer_eventfd_event(void *opaque, int event);

/*
 * DEBUG METHODS
 *
 * */
#ifdef DEBUG_NAGIANNI
static void nagianni_memory_dump(NagianniState *s, unsigned long size)
{
    unsigned char *p;
    unsigned long n;
    unsigned long addr = (unsigned long) s->shmem_ptr;

    size &= ~15; /* mod 16 */
    if (!size) return;

    p = (unsigned char *) addr;

    for (n = 0; n < size; n += 16) {
        printf(" %016lx: %02x %02x %02x %02x  %02x %02x %02x %02x "
                        "%02x %02x %02x %02x  %02x %02x %02x %02x\n",
               addr + n, p[n + 0], p[n + 1], p[n + 2], p[n + 3],
                         p[n + 4], p[n + 5], p[n + 6], p[n + 7],
                         p[n + 8], p[n + 9], p[n + 10], p[n + 11],
                         p[n + 12], p[n + 13], p[n + 14], p[n + 15]);
    }

    return;
}

static void debug_dev_mmio(SysBusDevice *device)
{
    int i = device->num_mmio;
    NAGIANNI_DPRINTF("device->num_mmio = %d, shared_mem_offset: %x\n",
                      device->num_mmio, SHARED_MEM_OFFSET);
    while (i)
    {
        NAGIANNI_DPRINTF("device->mmio[%d].addr = 0x%llx\n",
                         i-1, (long long unsigned int)device->mmio[i-1].addr);
        i--;
    }
}
#endif

/*
 * IRQ RELATED METHODS
 * trigger an interrupt
 * */
static void nagianni_update_irq(NagianniState *s)
{
    int isr;

    isr = (s->intrstatus & s->intrmask) & 0xffffffff;
    if (isr) {
        NAGIANNI_DPRINTF("Set IRQ to %d (%08x %08x)\n",
           isr ? 1 : 0, s->intrstatus, s->intrmask);
    }

    qemu_set_irq(s->irq, (isr != 0));
}

/*
 * write to mask register
 */
static void nagianni_intMask_write(NagianniState *state, uint32_t val)
{
    NAGIANNI_DPRINTF("writing to mask register\n");
    state->intrmask = val;
	nagianni_update_irq(state);
}

/*
 * read to mask register
 */
static uint32_t nagianni_intMask_read(NagianniState *state)
{
    NAGIANNI_DPRINTF("reading the mask register\n");
    return state->intrmask;
}

/*
 * write to status register
 */
static void nagianni_intStatus_write(NagianniState *state, uint32_t val)
{
    NAGIANNI_DPRINTF("writing to status register\n");
    state->intrstatus = val;
	nagianni_update_irq(state);
}

/*
 * read to status register
 */
static uint32_t nagianni_intStatus_read(NagianniState *state)
{
    uint32_t ret = state->intrstatus;

    NAGIANNI_DPRINTF("reading the status register\n");

    /* reading ISR clears all interrupts */
    state->intrstatus = 0;
	nagianni_update_irq(state);

    return ret;
}

/*
 * write to vmid register
 */
static void nagianni_intVmid_write(NagianniState *state, uint32_t val)
{
    NAGIANNI_DPRINTF("writing to vmid register\n");
    state->vm_id = val;
}

/*
 * read to vmid register
 */
static uint32_t nagianni_intVmid_read(NagianniState *state)
{
    NAGIANNI_DPRINTF("reading the vmid register\n");
    return state->vm_id;
}

/*
 * write to doorbell register
 */
static void nagianni_intDoorbell_write(NagianniState *state, uint32_t val)
{
    int ret;
    NAGIANNI_DPRINTF("writing to doorbell register\n");
    /*
     * The guest has written to the doorbell register.
     *
     * With the only purpose of testing the interrupt
     * qemu device -> external process,
     * we write in the eventfd file descriptor.
     * */
    ret = event_notifier_set(state->peer_eventfd);
    if (ret < 0) {
        NAGIANNI_DPRINTF("error while notifying the process...\n");
    }
    else {
        NAGIANNI_DPRINTF("notified\n");
    }
}

/*
 * read to doorbell register
 */
static uint32_t nagianni_intDoorbell_read(NagianniState *state)
{
    NAGIANNI_DPRINTF("reading the doorbell register\n");
    return state->doorbell;
}

static void nagianni_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    NagianniState *state = opaque;

    NAGIANNI_DPRINTF("nagianni write at addr: 0x%llx\n", (unsigned long long)addr);
    /* check destination address */
    switch(addr) {
        case INTRMASK:
            nagianni_intMask_write(state, data);
            break;

        case INTRSTATUS:
            nagianni_intStatus_write(state, data);
            break;

        case IVPOSITION:
            nagianni_intVmid_write(state, data);
            break;

        case DOORBELL:
            nagianni_intDoorbell_write(state, data);
            break;

        default:
            NAGIANNI_DPRINTF("writing unknown register\n");
    }
}

static uint64_t nagianni_read(void *opaque, hwaddr addr, unsigned size)
{
    NagianniState * state = opaque;
    uint32_t res = 0x0;

    NAGIANNI_DPRINTF("nagianni read at addr: 0x%llu\n", (unsigned long long)addr);
    switch(addr) {
        case INTRMASK:
            res = nagianni_intMask_read(state);
            break;

        case INTRSTATUS:
            res = nagianni_intStatus_read(state);
            break;

        case IVPOSITION:
            res = nagianni_intVmid_read(state);
            break;

        case DOORBELL:
            res = nagianni_intDoorbell_read(state);
            break;

        default:
            NAGIANNI_DPRINTF("reading unknown register\n");
    }

    /* disable interrupt */
    /* qemu_set_irq(*state->irqp[0], 0); */

    return res;
}

static const MemoryRegionOps nagianni_mem_ops = {
    .read       = nagianni_read,
    .write      = nagianni_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static Property nagianni_properties[] = {
    /*DEFINE_PROP_STRING("shm_name", NagianniState, shmobj),*/
    /*DEFINE_PROP_STRING("size", NagianniState, size_from_args),*/
    DEFINE_PROP_END_OF_LIST(),
};

/* check that the guest isn't going to try and map more memory than the
 * the object has allocated return -1 to indicate error
 */
static int check_shm_size(NagianniState *s, int fd)
{
    struct stat buf;

    fstat(fd, &buf);
    if (s->shm_size > buf.st_size) {
        fprintf(stderr,
                "NAGIANNI ERROR: Requested memory size greater"
                " than shared object size (%" PRIu64 " > %" PRIu64")\n",
                s->shm_size, (uint64_t)buf.st_size);
        return -1;
    }

    return 0;
}

/* create the bar and map the memory immediately */
static void create_shared_memory_region(NagianniState *s, int fd)
{
    void * ptr;

    s->shm_fd = fd;
    ptr = mmap(0, s->shm_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    memory_region_init_ram_ptr(&s->shm, OBJECT(s), "nagianni.shmem",
                               s->shm_size, ptr);
    vmstate_register_ram(&s->shm, DEVICE(s));
    memory_region_add_subregion(&s->bar, 0, &s->shm);

    /* region for shared memory */
    s->shmem_ptr = ptr;
    memset((void *)s->shmem_ptr, 0x0, s->shm_size);
}

static int init_shared_memory(NagianniState *s)
{
    int fd;

    if (s->shmobj == NULL) {
        fprintf(stderr, "Must specify 'chardev' or 'shm' to Nagianni\n");
        exit(1);
    }

    /* try opening with O_EXCL and if it succeeds zero the memory
     * by truncating to 0 */
    if ((fd = shm_open(s->shmobj, O_CREAT|O_RDWR|O_EXCL,
                       S_IRWXU|S_IRWXG|S_IRWXO)) > 0) {
        /* truncate file to length of device's memory */
        if (ftruncate(fd, s->shm_size) != 0) {
            fprintf(stderr, "Nagianni: could not truncate shared file\n");
        }
    } else if ((fd = shm_open(s->shmobj, O_CREAT|O_RDWR,
                    S_IRWXU|S_IRWXG|S_IRWXO)) < 0) {
        fprintf(stderr, "Nagianni: could not open shared file\n");
        exit(-1);
    }

    if (check_shm_size(s, fd) == -1) {
       fprintf(stderr, "Nagianni: shared memory check failed\n");
       exit(-1);
    }

    create_shared_memory_region(s, fd);
    return fd;
}

static int nagianni_init(SysBusDevice *device)
{
    DeviceState *dev = DEVICE(device);
    NagianniState *state = NAGIANNI(dev);

    state->shm_fd = 0;
    /* TODO: Remove the hard-coding */
    state->shmobj = (char *) "shmem";
    state->shm_size = SHARED_MEM_SIZE;

    /* init mmio region */
    memory_region_init_io(&state->mmio, OBJECT(device), &nagianni_mem_ops,
                          state, "nagianni", REGISTER_MEM_SIZE);
    sysbus_init_mmio(device, &state->mmio);

    /* init shared memory region */
    memory_region_init(&state->bar, OBJECT(state), "nagianni-bar2-container",
                        state->shm_size);
    init_shared_memory(state);
    sysbus_init_mmio(device, &state->bar);

    /* init IRQ */
    sysbus_init_irq(device, &state->irq);

    /* setup peer */
    nagianni_setup_peer(state);
    return 0;
}

static void nagianni_setup_peer(NagianniState *state)
{
    /* create a new char device */
    state->peer_chrdev = qemu_chr_new("peer", "unix:/tmp/peer_socket",
                                         NULL);
    /*
     * Instead of creating a new one, we can define one char device from
     * command line and then retrieve it.
     * */
    /*state->peer_chrdev = qemu_chr_find("peer_chrdev");*/

    if (state->peer_chrdev == NULL) {
        fprintf(stderr, "error while creating char dev device\n");
        return;
    }
    else {
        NAGIANNI_DPRINTF("using process socket %s with filename %s\n",
                         state->peer_chrdev->label,
                         state->peer_chrdev->filename);
    }

    qemu_chr_add_handlers(state->peer_chrdev, peer_canRead,
                          peer_read, peer_event, state);
}

static CharDriverState* create_chrdev_for_eventfd(NagianniState *status,
        EventNotifier *notifier, int vector)
{
    int eventfd = event_notifier_get_fd(notifier);

    /* Note: this fd is not meant to be read directly */
    status->eventfd_fd = eventfd;

    /* create a char device and return its pointer */
    CharDriverState * chr_dev_ptr = qemu_chr_open_eventfd(eventfd);
    if (chr_dev_ptr == NULL) {
        fprintf(stderr, "error while creating char dev device for eventfd\n");
        exit(-1);
    }

    chr_dev_ptr->label = (char *)"chardev eventfd";

    /*
     * without forcing the available connections value the execution will fail
     * at the qemu_chr_fe_claim_no_fail call.
     * Alternatively it is also possible to remove that call without the need
     * to set the number of available connections.
     * */
    chr_dev_ptr->avail_connections = 1;
    qemu_chr_fe_claim_no_fail(chr_dev_ptr);

    /* add handlers for incoming events */
    qemu_chr_add_handlers(chr_dev_ptr, peer_eventfd_canRead,
                          peer_eventfd_read, peer_eventfd_event, status);

    return chr_dev_ptr;
}

/*
 * HANDLER FOR EXTERNAL PROCESS / CHAR DEVICE
 *
 * read handler for the char device initiated
 * internally or by qemu command line. The other endpoint of
 * this socket is in the external process.
 * This if method is for receiving the eventfd file descriptor or
 * some data.
 * This is NOT the read operation of the eventfd file descriptor itself.
 * */
static void peer_read(void *opaque, const uint8_t *buf, int size)
{
    NagianniState *state = opaque;
    int received_fd, tmp_fd;

    /*receive the fd from the chardev*/
    tmp_fd = qemu_chr_fe_get_msgfd(state->peer_chrdev);

    if (tmp_fd == -1) {
        NAGIANNI_DPRINTF("unable to retrieve peer fd,\
                looking for incoming data\n");
    }
    else {
        NAGIANNI_DPRINTF("retrived peer fd = %x\n", tmp_fd);

        received_fd = dup(tmp_fd);
        if (received_fd == -1) {
            fprintf(stderr, "error while allocating: %sfd\n", strerror(errno));
        }

        /* create and init the eventNotifier*/
        state->peer_eventfd = g_new(EventNotifier, 1);
        event_notifier_init_fd(state->peer_eventfd, received_fd);

        /* create a char device to receive the incoming signal*/
        state->peer_eventfd_chrdev = create_chrdev_for_eventfd(state,
                state->peer_eventfd, 0);
    }
}

/*
 * HANDLER FOR EXTERNAL PROCESS / CHAR DEVICE
 * */
static void peer_event(void *opaque, int event)
{
    NAGIANNI_DPRINTF("peer event %d triggered\n", event);
}

/*
 * HANDLER FOR EXTERNAL PROCESS / CHAR DEVICE
 * */
static int peer_canRead(void *opaque)
{
    return 8;
}

/*
 * HANDLER FOR **peer** EVENTFD EVENTS
 *
 * read handler
 **/
static void peer_eventfd_read(void *opaque, const uint8_t * buf, int size)
{
    int i;
    for (i = 0; i < size; i++) {
        NAGIANNI_DPRINTF("buffer[%d]: 0x%02x\n", i, buf[i]);
    }
}

/*
 * HANDLER FOR **peer** EVENTFD EVENTS
 */
static int peer_eventfd_canRead(void *opaque)
{
    return peer_canRead(opaque);
}

/*
 * HANDLER FOR **peer** EVENTFD EVENTS
 */
static void peer_eventfd_event(void *opaque, int event)
{
    NAGIANNI_DPRINTF("peer-eventfd event %d triggered\n", event);
}

static void nagianni_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = nagianni_init;
    dc->props = nagianni_properties;
    /*
     * TODO dc->vmsd = &vmstate_nagianni;
     **/
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo nagianni_info = {
    .name       = TYPE_NAGIANNI,
    .parent     = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(NagianniState),
    .class_init = nagianni_class_init,
};

static void nagianni_register_types(void)
{
    type_register_static(&nagianni_info);
}

void nagianni_legacy_init(uint32_t base, qemu_irq irq)
{
    DeviceState *dev;
    SysBusDevice *bus;

    dev = qdev_create(NULL, TYPE_NAGIANNI);
    qdev_init_nofail(dev);
    bus = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(bus, 0, base);
    sysbus_mmio_map(bus, 1, base + SHARED_MEM_OFFSET);
    sysbus_connect_irq(bus, 0, irq);
}
type_init(nagianni_register_types)

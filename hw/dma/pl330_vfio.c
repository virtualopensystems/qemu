/*
 * PL330 DMA controller VFIO device
 *
 * Authors:
 *      Alvise Rigo, Copyright (c) 2013 Virtual Open Systems
 *
 * This code is licensed under the GNU GPL v2.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "hw/sysbus.h"
#include "hw/devices.h"
#include "hw/arm/primecell.h"
#include "sysemu/sysemu.h"
#include "sysemu/char.h"
#include <sys/types.h>
#include <sys/mman.h>

#include <linux/vfio.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <glib.h>
#include <linux/types.h>

#include "sysemu/dma.h"

#define DEBUG_PL330_VFIO
#ifdef DEBUG_PL330_VFIO
#define PL330_VFIO_DPRINTF(fmt, ...)  \
    do {printf("PL330_VFIO: " fmt, ## __VA_ARGS__); } while (0)
#else
    #define DEBUG_PL330_VFIO(fmt, ...)
#endif

#define TYPE_PL330_VFIO "pl330"
#define PL330VFIO(obj) \
    OBJECT_CHECK(PL330VFIOState, (obj), TYPE_PL330_VFIO)

#define VFIO_FAIL			((void *)-1)
#define VFIO_DMA_MAP_FLAG_EXEC		(1 << 2)        /* executable from device */
#define VFIO_DEF_MASK			((VFIO_DMA_MAP_FLAG_READ) | (VFIO_DMA_MAP_FLAG_WRITE)\
							| (VFIO_DMA_MAP_FLAG_EXEC))

/* device specific configuration */
#define PL330_VFIO_MEMSIZE		0x1000
#define PL330_MAX_CHANNELS		8
// this should not be hard coded TODO
#define PL330_MAX_IRQS			5 // at least, the device tree has 5 set
// buffer size per request, specified in kernel driver
#define PL330_BUFF_REQUEST_SIZE		256

/*
 * This structure represent a physical memory area of the guest
 * which has to be DMA mapped
 * */
typedef struct guest_phys_mem_area{
	hwaddr addr;
	hwaddr size;
} guest_phys_area;

struct guest_mapping{
	hwaddr addr;
	hwaddr size;
	void *guest_ptr;
};

struct container_guest_mappings{
	struct guest_mapping *mappings;
	int num_mappings;
};

struct addr_range {
	hwaddr start;
	hwaddr size;
};

typedef struct PL330VFIOState {
	SysBusDevice parent_obj;

	/* Registers memory */
	MemoryRegion mmio;
	MemoryRegion regs_mem;

	/* 32bit registers */
	void *regs;

	struct debug_ins_request *pending_request;

	// VFIO
	char *group_str;
	char *device_str;
	char *container_str;

	int container, group, device;
	struct vfio_device_info device_info;

	// irq
	qemu_irq irq[PL330_MAX_IRQS];

	GHashTable *mapped_regions;

	// eventfd - irq support
	fd_set set_irq_efd;
	int highest_irq_num;
	pthread_t irq_handler;
	GHashTable *efdnum_irqnum;
} PL330VFIOState;


/*
 * A request from the kernel driver comes always in a set
 * of 3 writes in the following registers:
 * - DBGINST0
 * - DBGINST1
 * - DBGCMD
 * We can consider these 3 writes as atomic.
 * */
struct debug_ins_request {
	uint32_t dbginst0;
	uint32_t dbginst1;
	uint32_t dbgcmd;

	bool to_submit;
	bool for_manager;
	uint32_t channel;
};

static void *get_pl330_reg_ptr(PL330VFIOState *state);
static int get_src_dst_addrs(uint32_t cmds_addr, hwaddr *src, hwaddr *dst);
static int update_guest_mapped_mem(PL330VFIOState *state, hwaddr start_addr, hwaddr size);
static int add_eventfd_irq(PL330VFIOState *state, int eventfd_irq, int vfio_irq_index);
void pl330_vfio_start_irq_handler(PL330VFIOState *state);
static void vfio_irqfd_init(int device, unsigned int index, int fd);
int start_irq_handler(PL330VFIOState *state);
static void vfio_irq_unmask(int device, unsigned int index);

static const struct debug_ins_request debug_ins_req_blank = {
	.dbginst0 = 0,
	.dbginst1 = 0,
	.dbgcmd = 0,
	.to_submit = false,
	.for_manager = false,
	.channel = 0,
};

static uint64_t pl330_vfio_iomem_read(void *opaque, hwaddr addr, unsigned size)
{
	/*
	 * Here we allow to read the whole registers area to the guest driver
	 * */
	PL330VFIOState *state = (PL330VFIOState *)opaque;
	int ret = *((int *)(state->regs + addr));
	PL330_VFIO_DPRINTF("read - offset 0x%llx\n", (unsigned long long)addr);

	return ret;
}

struct efdnum_irqnum {
	int efdnum;
	int irqnum;
};

static void find_efdnum(gpointer key, gpointer val, gpointer irqnum_efdnum)
{
	if(*(int *)val == ((struct efdnum_irqnum *)irqnum_efdnum)->irqnum) {
		((struct efdnum_irqnum *)irqnum_efdnum)->efdnum = *(int *)key;
	}
}

static struct addr_range get_region_range(hwaddr addr)
{
	MemoryRegion *system_mem = NULL;

	struct addr_range range;
	hwaddr size;

	MemoryRegion *mem_region_found;

	system_mem = get_system_memory();
	mem_region_found = memory_region_find(system_mem, addr, 1).mr;

	PL330_VFIO_DPRINTF("region found - name: %s, "
		" (hw)addr: %llx "
		"ram_addr: %x\n", mem_region_found->name,
		mem_region_found->addr, mem_region_found->ram_addr);

	size = int128_get64(int128_sub(mem_region_found->size, int128_one()));

	range.start = mem_region_found->addr;
	// why doesn't it tell the truth about the size?
	range.size = size + 1;

	return range;
}

/*
 * Every (debug) request, to be submitted, will ALWAYS write
 * in the following registers in this order:
 * DBGINST0, DBGINST1, DBGCMD
 * */
#define DBGCMD			0xD04
#define DBGINST0		0xD08
#define DBGINST1		0xD0C
#define INTCLR			0x02C
static void pl330_vfio_iomem_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
	PL330VFIOState *state = (PL330VFIOState *)opaque;
	PL330_VFIO_DPRINTF("write - data %llx - offset %llx\n", (unsigned long long)data,
							(unsigned long long)addr);

	struct debug_ins_request *req = state->pending_request;

	int irqnum;
	struct efdnum_irqnum efdnum_irqnum = {0, 0};
	switch(addr) {
	case INTCLR:
		irqnum = __builtin_ctz(data);
		PL330_VFIO_DPRINTF("clearing irq idx: %d\n", irqnum);

		// disable in real hw first
		*((int *)(state->regs + addr)) = (uint32_t)data;

		// disable in qemu
		qemu_set_irq(state->irq[irqnum], 0);

		// unmask the interrupt
		vfio_irq_unmask(state->device, irqnum);

		struct vfio_irq_info irq = { .argsz = sizeof(irq), .index = irqnum };

		int ret = ioctl(state->device, VFIO_DEVICE_GET_IRQ_INFO, &irq);

		if (ret) {
			PL330_VFIO_DPRINTF("ioctl irq error!\n");
			qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: irq error");
		}

		efdnum_irqnum.irqnum = irqnum;
		g_hash_table_foreach(state->efdnum_irqnum, find_efdnum, &efdnum_irqnum);

		vfio_irqfd_init(state->device, irq.index, efdnum_irqnum.efdnum);

		break;
	case DBGINST0:
		if(!req->to_submit && !req->dbginst0
				&& !req->dbginst1) {
			req->for_manager = (data & 0x1) ? false : true;
			if(!req->for_manager) {
				req->channel = ((data >> 8) & 0x7);
				PL330_VFIO_DPRINTF("request for channel %d\n", req->channel);
			} else {
				PL330_VFIO_DPRINTF("request for manager\n");
			}
			req->dbginst0 = data;
		}
		else {
			qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: request error");
		}
		break;
	case DBGINST1:
		if(!req->to_submit && req->dbginst0
				&& !req->dbginst1) {
			req->dbginst1 = data;
			req->to_submit = true;
		}
		else {
			// error
			qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: request error");
		}
		break;
	case DBGCMD:
		if (req->to_submit) {
			/*int ret1;*/
			hwaddr src = 0, dst = 0;
					/*uint32_t page_size;*/

			if(get_src_dst_addrs(req->dbginst1, &src, &dst)) {
				PL330_VFIO_DPRINTF("this is not a transfer request\n");
				*((int *)(state->regs + DBGINST0)) = req->dbginst0;
				*((int *)(state->regs + DBGINST1)) = req->dbginst1;
				*((int *)(state->regs + DBGCMD)) = (uint32_t)data;

				// clear the request
				*req = debug_ins_req_blank;

				return;
			}

			struct addr_range src_range = get_region_range(src);
			struct addr_range dst_range = get_region_range(dst);

			if(update_guest_mapped_mem(state, src_range.start, src_range.size) ||
			   update_guest_mapped_mem(state, dst_range.start, dst_range.size)) {
				// error
				PL330_VFIO_DPRINTF("error while updating guest map\n");
				qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: error while VFIO-mapping");
			}

			// flush the request to the real device
			*((int *)(state->regs + DBGINST0)) = req->dbginst0;
			*((int *)(state->regs + DBGINST1)) = req->dbginst1;
			*((int *)(state->regs + DBGCMD)) = (uint32_t)data;

			// clear the pending request
			*req = debug_ins_req_blank;
		} else {
			// some strange error occurred
			qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: request error");
		}
		break;
	default:
		*((int *)(state->regs + addr)) = (uint32_t)data;
		break;
	}
}

static const MemoryRegionOps pl330_vfio_mem_ops = {
	.read	= pl330_vfio_iomem_read,
	.write	= pl330_vfio_iomem_write,
	.impl	= {
		.min_access_size = 4,
		.max_access_size = 4,
	},
};

static void pl330_vfio_realize(DeviceState *dev, Error **errp)
{
	void *regs = NULL;
	int i, ret;
	PL330VFIOState *state = PL330VFIO(dev);
	SysBusDevice *sys_dev = SYS_BUS_DEVICE(dev);

	regs = get_pl330_reg_ptr(state);
	if(regs == VFIO_FAIL) {
		error_setg(errp, "Error while probing real device.\n");
		return;
	}
	state->regs = regs;

	/* init mmio region */
	memory_region_init_io(&state->mmio, OBJECT(state), &pl330_vfio_mem_ops,
			state, "dma-vfio", PL330_VFIO_MEMSIZE);

	sysbus_init_mmio(sys_dev, &state->mmio);

	/* init irq */
	for(i = 0; i < PL330_MAX_IRQS; i++) {
		sysbus_init_irq(sys_dev, &state->irq[i]); // we require only the first atm
	}

	state->pending_request = g_malloc0(sizeof(struct debug_ins_request));

	// create hash table to store allocated regions
	state->mapped_regions = g_hash_table_new_full(g_int64_hash, g_int64_equal,
			free, free);

	FD_ZERO(&state->set_irq_efd);
	state->highest_irq_num = 0;
	state->efdnum_irqnum = g_hash_table_new_full(g_int_hash, g_int_equal,
			free, free);

	if(PL330_MAX_IRQS > state->device_info.num_irqs) {
		/*
		 * the device supports less irqs than the device tree says
		 * */
		error_setg(errp, "not enough irq line of the real device\n");
		return;
	}

	for(i = 0; i < PL330_MAX_IRQS; i++) {
		struct vfio_irq_info irq = { .argsz = sizeof(irq) };

		irq.index = i;

		ret = ioctl(state->device, VFIO_DEVICE_GET_IRQ_INFO, &irq);

		if (ret) {
			error_setg(errp, "ioctl irq\n");
			return;
		}

		PL330_VFIO_DPRINTF("- IRQ %d: range of %d, flags=0x%x\n",
				irq.index,
				irq.count,
				irq.flags );

		int irqfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (irqfd < 0)
			error_setg(errp, "eventf irq\n");

		vfio_irqfd_init(state->device, irq.index, irqfd);

		/*
		 * Init irq QEMU side
		 * */
		sysbus_init_irq(sys_dev, &state->irq[irq.index]);
		if (add_eventfd_irq(state, irqfd, irq.index)) {
			error_setg(errp, "IRQ error\n");
			return;
		}
	}
	// start irq handler
	start_irq_handler(state);

	for(i = 0; i < PL330_MAX_IRQS; i++) {
		sysbus_connect_irq(sys_dev, 0, pl330_irq[i]);
	}

	sysbus_mmio_map(sys_dev, 0, 0x7ffb0000);
}

static Property pl330_vfio_properties[] = {
	DEFINE_PROP_STRING("vfio_group", PL330VFIOState, group_str),
	DEFINE_PROP_STRING("vfio_device", PL330VFIOState, device_str),
	DEFINE_PROP_STRING("vfio_container", PL330VFIOState, container_str),
	DEFINE_PROP_END_OF_LIST(),
};

static void pl330_vfio_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = pl330_vfio_realize;
    dc->props = pl330_vfio_properties;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo pl330_vfio_info = {
    .name       = TYPE_PL330_VFIO,
    .parent     = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PL330VFIOState),
    .class_init = pl330_vfio_class_init,
};

static void pl330_vfio_register_types(void)
{
    type_register_static(&pl330_vfio_info);
}

/*
 * This method takes the hw guest address pointing
 * to the set of the instructions generated by the 
 * guest driver and returns the guest hw address of
 * source and destination used in the DMA transfer.
 *
 * This is useful to set the DMA mapping.
 * */
#define SAR			0
#define DAR			2
#define DMAMOV_CMD		0xBC
#define DMAEND_CMD		0x0
static int get_src_dst_addrs(uint32_t cmds_addr, hwaddr *src, hwaddr *dst) {
	// find the DMADST instruction
	int i;
	bool not_found = false;
	hwaddr _dst, _src;
	int len = PL330_BUFF_REQUEST_SIZE;
	uint8_t buffer[len];
	uint8_t *ptr = buffer;

	dma_memory_read(&address_space_memory, (hwaddr)cmds_addr, ptr, len);

	// TODO set an upper limit of the search if DMAMOV and
	i = 0;
	while(ptr[i] != DMAMOV_CMD || (ptr[i + 1] & 0x7) != SAR) {
		if(i == len - 1) {
			not_found = true;
			break;
		}
		i++;
	}

	if(!not_found) {
		_src = *((uint32_t *)(&ptr[i + 2]));
	} else {
		return -1;
	}

	i += 6; // DMAMOV is 6 bytes long
	while(ptr[i] != DMAMOV_CMD || (ptr[i + 1] & 0x7) != DAR) {
		if(i == len - 1) {
			not_found = true;
			break;
		}
		i++;
	}

	if(!not_found) {
		_dst = *((uint32_t *)(&ptr[i + 2]));
	} else {
		return -1;
	}

	*dst = _dst;
	*src = _src;

	return 0;
}

static void print_region_map(gpointer key, gpointer val, gpointer no_data)
{
	int i;
	struct container_guest_mappings *maps = val;

	PL330_VFIO_DPRINTF("region key: %llu, num. segments: %d\n", *(hwaddr *)key,
							maps->num_mappings);

	struct guest_mapping *mapped_segment;
	for(i = 0; i < maps->num_mappings; i++){
		mapped_segment = &maps->mappings[i];
		PL330_VFIO_DPRINTF("\n     seg num.%d, addr: %llx, size: %llu\n", i,
				mapped_segment->addr, mapped_segment->size);
	}

}

static void print_map_status(PL330VFIOState *state)
{
	g_hash_table_foreach(state->mapped_regions, print_region_map, NULL);
}

/* VFIO helper functions */
static int update_guest_mapped_mem(PL330VFIOState *state, hwaddr start_addr, hwaddr size)
{
	bool exit_mapping;
	bool map = true;

	hwaddr *key = g_malloc(sizeof(hwaddr));
	*key = start_addr ^ size;
	if(g_hash_table_lookup_extended(state->mapped_regions, key, NULL, NULL)) {
		// this region has already been mapped
		PL330_VFIO_DPRINTF("this region has already been mapped\n");
		map = false;
	}

	if(map) {
		struct vfio_iommu_type1_dma_map update = { .argsz = sizeof(update) };
		hwaddr step_size = 0, new_start, remaining;
		void *ptr = NULL;

		struct container_guest_mappings *new_mapping;
		new_mapping = g_malloc(sizeof(struct container_guest_mappings));
		new_mapping->num_mappings = 0;
		/* multiple mappings for a single region are not going to
		happen frequently, we ask only for one */
		new_mapping->mappings = g_malloc0(sizeof(struct guest_mapping));

		/*
		 * The following cpu_phys_mem_map request may non satisfy completely
		 * the requested size: in this case we need to do multiple requests.
		 * */
		exit_mapping = false;
		new_start = start_addr;
		remaining = step_size = size;
		while(!exit_mapping) {
			ptr = cpu_physical_memory_map(new_start, &step_size, 0);

			if(ptr == NULL) {
				qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: mapping error"); 
				return -1;
			}

			struct guest_mapping new_map;
			new_map.guest_ptr = ptr;
			new_map.addr = new_start;
			new_map.size = step_size;
			if(new_mapping->num_mappings) {
				new_mapping->mappings = g_realloc(new_mapping->mappings,
					(new_mapping->num_mappings + 1) * sizeof(struct guest_mapping));
			}
			new_mapping->mappings[new_mapping->num_mappings] = new_map;
			new_mapping->num_mappings++;

			update.vaddr = (uintptr_t)ptr;
			update.flags = VFIO_DEF_MASK;
			update.iova = new_start;
			update.size = step_size;

			PL330_VFIO_DPRINTF("dma map: vaddr: 0x%llx, iova: 0x%llx, size: %llu\
					, remaining: %llu\n", update.vaddr, update.iova, update.size, remaining);
			qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: mapping error"); 

			if(ioctl(state->container, VFIO_IOMMU_MAP_DMA, &update)) {
				PL330_VFIO_DPRINTF("error while updating dma-map\n");
				qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: mapping error"); 

				return -1;
			}

			if(remaining > step_size) {
				remaining -= step_size;
			}
			else {
				exit_mapping = true;
			}
			new_start += step_size;
		}

		g_hash_table_insert(state->mapped_regions, key, new_mapping);
	} else {
		PL330_VFIO_DPRINTF("no update necessary\n");
	}

	print_map_status(state);

	return 0;
}

static void *get_pl330_reg_ptr(PL330VFIOState *state)
{
	void *ptr = NULL;
	int ret;
	int container, group, device;
	// group id
	const char *group_str = state->group_str;
	// device id
	const char *device_str = state->device_str;
	// vfio container
	const char *container_str = state->container_str;

	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };

	container = open(container_str, O_RDWR);
	state->container = container;

	if (ioctl(container, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
		PL330_VFIO_DPRINTF("Unknown API version\n");
		ptr = VFIO_FAIL;
		goto out;
	}

	if (!ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		PL330_VFIO_DPRINTF("Doesn't support the IOMMU driver we want\n");
		ptr = VFIO_FAIL;
		goto out;
	}

	/* Open the group */
	group = open(group_str, O_RDWR);
	state->group = group;

	/* Test the group is viable and available */
	ioctl(group, VFIO_GROUP_GET_STATUS, &group_status);

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		PL330_VFIO_DPRINTF("Group is not viable (not all devices bound for vfio)\n");
		ptr = VFIO_FAIL;
		goto out;
	}

	/* Add the group to the container */
	ioctl(group, VFIO_GROUP_SET_CONTAINER, &container);

	/* Enable the IOMMU model we want */
	ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);

	/* Get addition IOMMU info */
	ioctl(container, VFIO_IOMMU_GET_INFO, &iommu_info);

	/* Get a file descriptor for the device */
	device = ioctl(group, VFIO_GROUP_GET_DEVICE_FD, device_str);
	state->device = device;
	PL330_VFIO_DPRINTF("=== VFIO device file descriptor %d ===\n", device);

	/* Test and setup the device */
	ret = ioctl(device, VFIO_DEVICE_GET_INFO, &device_info);

	if(ret) {
		PL330_VFIO_DPRINTF("Could not get VFIO device\n");
		ptr = VFIO_FAIL;
		goto out;
	}
	state->device_info = device_info;

	printf("Device has %d region(s):\n", device_info.num_regions);

	struct vfio_region_info reg = { .argsz = sizeof(reg) };
	reg.index = 0;
	ret = ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &reg);

	if(ret) {
		PL330_VFIO_DPRINTF("Couldn't get region %d info\n", reg.index);
		ptr = VFIO_FAIL;
		goto out;
	}

	PL330_VFIO_DPRINTF("- Region %d: size=0x%llx offset=0x%llx flags=0x%x\n",
			reg.index,
			reg.size,
			reg.offset,
			reg.flags );

	ptr = mmap(NULL, reg.size, PROT_READ | PROT_WRITE, MAP_SHARED,
						device, reg.offset);

out:
	return ptr;
}

static void fdset_insert(gpointer key, gpointer val, gpointer state_ptr)
{
	PL330VFIOState *state = (PL330VFIOState *)state_ptr;

	FD_SET(*(int *)key, &state->set_irq_efd);
}

static void restore_fdset(PL330VFIOState *state)
{
	FD_ZERO(&state->set_irq_efd);

	g_hash_table_foreach(state->efdnum_irqnum, fdset_insert,
							state);
}

/*
 * add new irq to the triggering set.
 * */
int add_eventfd_irq(PL330VFIOState *state, int eventfd_irq, int vfio_irq_index)
{
	int *efd_ptr = NULL;
	int *irq_idx_ptr = NULL;

	if(FD_ISSET(eventfd_irq, &(state->set_irq_efd))) {
		return -1;
	}
	FD_SET(eventfd_irq, &state->set_irq_efd);

	efd_ptr = malloc(sizeof(*efd_ptr));
	*efd_ptr = eventfd_irq;
	irq_idx_ptr = malloc(sizeof(*irq_idx_ptr));
	*irq_idx_ptr = vfio_irq_index;

	g_hash_table_insert(state->efdnum_irqnum, efd_ptr,
						irq_idx_ptr);

	if(eventfd_irq > state->highest_irq_num) {
		state->highest_irq_num = eventfd_irq;
	}

	return 0;
}

static void qemu_trigger_irq(gpointer key, gpointer val, gpointer state_ptr)
{
	PL330VFIOState *state = (PL330VFIOState *)state_ptr;

	// the fdset has only the triggered file descriptors
	if(FD_ISSET(*(int *)key, &state->set_irq_efd)) {
		// qemu-trigger the interrupt
		qemu_set_irq(state->irq[*(int *)val], 1);
		PL330_VFIO_DPRINTF("triggered irq %d\n", *(int *)val);

		// disable eventfd
		eventfd_t eval;
		if(eventfd_read(*(int *)key, &eval)) {
			PL330_VFIO_DPRINTF("error while reading from eventfd\n");
		}
	}
}

static void *irq_handler_func(void *arg)
{
	PL330VFIOState *state = (PL330VFIOState *)arg;

	while (1) {
		/*
		 * waiting for I/O, in this case for the notification
		 * of an interrupt
		 * */
		select(state->highest_irq_num + 1, &state->set_irq_efd,
						NULL, NULL, NULL);
		PL330_VFIO_DPRINTF("TRIGGER!\n");

		g_hash_table_foreach(state->efdnum_irqnum, qemu_trigger_irq,
							state);
		restore_fdset(state);
	}

	return NULL;
}

static void vfio_irq_unmask(int device, unsigned int index)
{
	struct vfio_irq_set irq_set = {
		.argsz = sizeof(irq_set),
		.flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK,
		.index = index,
		.start = 0,
		.count = 1,
	};
	int ret = ioctl(device, VFIO_DEVICE_SET_IRQS, &irq_set);
	if (ret) {
		qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: error while unmasking"); 
	}
}

int start_irq_handler(PL330VFIOState *state)
{
	int ret;

	ret = pthread_create(&state->irq_handler, NULL, irq_handler_func, state);
	
	if(ret) {
		PL330_VFIO_DPRINTF("error while creating thread\n");
		qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: error while creating irq handler"); 

		return -1;
	}
	
	return 0;
}

static void vfio_irqfd_init(int device, unsigned int index, int fd)
{
	struct vfio_irq_set *irq_set;
	int32_t *pfd;
	int ret, argsz;

	argsz = sizeof(*irq_set) + sizeof(*pfd);
	irq_set = malloc(argsz);

	if (!irq_set) {
		PL330_VFIO_DPRINTF("failure while allocating memory for irq\n");
		qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: failure while allocating memory for irq"); 

		return;
	}

	irq_set->argsz = argsz;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = index;
	irq_set->start = 0;
	irq_set->count = 1;
	pfd = (int32_t *)&irq_set->data;
	*pfd = fd;

	ret = ioctl(device, VFIO_DEVICE_SET_IRQS, irq_set);
	free(irq_set);

	if (ret) {
		PL330_VFIO_DPRINTF("IRQ failure\n");
		qemu_log_mask(LOG_GUEST_ERROR, "VFIO pl330: IRQ failure"); 
		return;
	}
}


type_init(pl330_vfio_register_types)

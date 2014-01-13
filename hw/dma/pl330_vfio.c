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

/*#define VENDOR_ID_PL330_VFIO something*/

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
#define PL330_MAX_IRQS			5 // at least, the device tree has 5 set
// buffer size per request, specified in kernel driver
#define PL330_BUFF_REQUEST_SIZE		256
#define MEGA				((1024)*(1024))
#define PL330_MAX_TRANSFER_SIZE		((20)*(MEGA))	
#define MAPPING_BUFFER_SIZE		32

#define VFIO_GROUP			"/dev/vfio/0"
#define VFIO_DEVICE			"2c0a0000.dma"
#define VFIO_CONTAINER			"/dev/vfio/vfio"

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
	int container, group, device;
	struct vfio_device_info device_info;

	// irq
	qemu_irq irq[PL330_MAX_IRQS];

	// guest mapped memory
	guest_phys_area guest_mapped_mem;
	struct container_guest_mappings guest_mappings;
	/*struct vfio_iommu_type1_dma_map vfio_dma_map;*/

	/*void *guest_ptr;*/

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
static int get_dst_addr(uint32_t cmds_addr, hwaddr *src, hwaddr *dst);
static int update_guest_mapped_mem(PL330VFIOState *state, hwaddr start_addr, hwaddr size);
static int add_eventfd_irq(PL330VFIOState *state, int eventfd_irq, int vfio_irq_index);
void pl330_vfio_start_irq_handler(PL330VFIOState *state);
static void vfio_irqfd_init(int device, unsigned int index, int fd);
int start_irq_handler(PL330VFIOState *state);

static int comp_ptr(const void *a, const void *b)
{
	if((*(guest_phys_area **)a)->addr < (*(guest_phys_area **)b)->addr) {
		return -1;
	}
	else if((*(guest_phys_area **)a)->addr > (*(guest_phys_area **)b)->addr){
		return 1;
	}
	return 0;
}

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
	/*MemoryRegion *sub_mem_region = NULL;*/
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

	/*QTAILQ_FOREACH(sub_mem_region, &mem_region_found->subregions, subregions_link) {
		if(sub_mem_region != NULL && sub_mem_region->ram) {
			hwaddr size = int128_get64(int128_sub(sub_mem_region->size, int128_one()));
			if(sub_mem_region->alias) {
				PL330_VFIO_DPRINTF("ram subregion - name: %s, alias: %s, alias_offset: %llx"
						" (hw)addr: %llx, "
						"ram_addr: %x, size: %llx\n", sub_mem_region->name,
						sub_mem_region->alias->name,
						sub_mem_region->alias_offset,
						sub_mem_region->addr,
						sub_mem_region->ram_addr, size);
			} else {
				PL330_VFIO_DPRINTF("ram subregion - name: %s, "
						" (hw)addr: %llx - %llx, "
						"ram_addr: %x, size: %llx\n", sub_mem_region->name,
						sub_mem_region->addr, sub_mem_region->addr + size,
						sub_mem_region->ram_addr, size);
			}
		}
	}*/
}

/*
 * Every debug request, to be submitted, will ALWAYS write
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
	/*
	 * The way usually the controller is instructed to make a memory
	 * transfer is as follow:
	 *
	 * - the user of the controller (in our case the guest kernel driver)
	 *   builds all the command to realize the transfer and put them in a
	 *   local buffer.
	 *   	-> we need to access to this buffer using 
	 *   			dma_memory_read(&address_space_memory,
	 *   			memory_address, *buffer, len);
	 * 
	 * - the user build also some DEBUG commands to inform the controller
	 *   of the position of the above commands, and writes them directly
	 *   in some debug registers. (Before doing that, it has also to read
	 *   some data from a registers...)
	 *
	 * */
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

		// fin qua tutto bene...ma la seconda volta che provo ad eseguire il
		// test, l'irq risulta disabilitata dall'iterazione precedente (vfio_platform_irq.c
		// riga ~100. Devo riabilitarla (unmask) e il codice  qui sotto non 
		// funziona.
		// con questo codice l'irq viene triggerata (e quindi viene attivato il corrispettivo
		// eventfd, ma il select() non si smuove.

		struct vfio_irq_info irq = { .argsz = sizeof(irq), .index = irqnum };

		int ret = ioctl(state->device, VFIO_DEVICE_GET_IRQ_INFO, &irq);

		if (ret) {
        		PL330_VFIO_DPRINTF("ioctl irq error!\n");
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
			// error
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
		}
		break;
	case DBGCMD:
		if (req->to_submit) {
			/*int ret1;*/
			hwaddr src = 0, dst = 0;
			uint32_t page_size;

			if(get_dst_addr(req->dbginst1, &src, &dst)) {
				PL330_VFIO_DPRINTF("this is not a transfer request\n");
				*((int *)(state->regs + DBGINST0)) = req->dbginst0;
				*((int *)(state->regs + DBGINST1)) = req->dbginst1;
				*((int *)(state->regs + DBGCMD)) = (uint32_t)data;

				// clear the request
				*req = debug_ins_req_blank;

				return;
			}

			page_size = getpagesize();
			/* memory areas of the guest that we have to map */
			guest_phys_area src_guest_area = {src, PL330_MAX_TRANSFER_SIZE};
			guest_phys_area dst_guest_area = {dst, PL330_MAX_TRANSFER_SIZE};
			guest_phys_area ins_guest_area = {req->dbginst1,
						PL330_BUFF_REQUEST_SIZE};

			guest_phys_area *areas[3] = {&src_guest_area, &dst_guest_area,
								&ins_guest_area};
			qsort(areas, 3, sizeof(guest_phys_area *), comp_ptr);

			/* 
			 * To reduce number of mapping, we make only one request.
			 * In order to have a successful map, we need to have
			 * iova, vaddr and size page aligned
			 * */

			// get the lower address and find the offset to align it to the page
			hwaddr to_align_padding = areas[0]->addr & (page_size - 1);

			// calculate the minimum area to map
			hwaddr start_addr = areas[0]->addr - to_align_padding;
			hwaddr min_mapped_size = (areas[2]->addr + areas[2]->size)
									- start_addr;

			hwaddr mapped_size;
			if(min_mapped_size % page_size)	{
				mapped_size = (min_mapped_size / page_size + 1) * page_size;
			}
			else {
				mapped_size = min_mapped_size;
			}

			PL330_VFIO_DPRINTF("min mapped size %lluB, mapped size: %lluB, start addr: 0x%llx\n",
						min_mapped_size, mapped_size, start_addr);

			// we map one page before
			start_addr -= page_size;
			mapped_size += page_size;

			struct addr_range range = get_region_range(start_addr);

			/*if(update_guest_mapped_mem(state, start_addr, mapped_size)) {*/
			if(update_guest_mapped_mem(state, range.start, range.size)) {
				// error
				PL330_VFIO_DPRINTF("error while updating guest map\n");
			}
			
			// flush the request to the real device
			*((int *)(state->regs + DBGINST0)) = req->dbginst0;
			*((int *)(state->regs + DBGINST1)) = req->dbginst1;
			*((int *)(state->regs + DBGCMD)) = (uint32_t)data;

			// clear the pending request
			*req = debug_ins_req_blank;
		} else {
			// error
		}
		break;
	default:
		*((int *)(state->regs + addr)) = (uint32_t)data;
		break;
	}
}

static const MemoryRegionOps pl330_vfio_mem_ops = {
	.read 	= pl330_vfio_iomem_read,
	.write 	= pl330_vfio_iomem_write,
	.impl 	= { 
		.min_access_size = 4,
		.max_access_size = 4,
		// .unaligned = false,
	},
};

static void pl330_vfio_realize(DeviceState *dev, Error **errp)
{
	void *regs = NULL;
	int i, ret;
	PL330VFIOState *state = PL330VFIO(dev);
    	SysBusDevice *sys_dev = SYS_BUS_DEVICE(dev);
	PL330_VFIO_DPRINTF("realizing device\n");

	regs = get_pl330_reg_ptr(state);
	if(regs == VFIO_FAIL) { 
        	error_setg(errp, "Error while probing real device.\n");
		return;
	}
	state->regs = regs;

    	/* init mmio region */
    	memory_region_init_io(&state->mmio, OBJECT(state), &pl330_vfio_mem_ops,
    	                      state, "dma-vfio", PL330_VFIO_MEMSIZE);
	/*
	 * To speed up the read and write accesses made by the guest
	 * we can map into the region the memory directly
	 * */
    	sysbus_init_mmio(sys_dev, &state->mmio);

    	/* init irq */
	sysbus_init_irq(sys_dev, &state->irq[0]); // we require only the first atm
	for(i = 0; i < PL330_MAX_IRQS; i++) {
		
	}

	state->pending_request = g_malloc0(sizeof(struct debug_ins_request));

	// at the beginning there is no memory of the guest mapped
	state->guest_mapped_mem.addr = 0;
	state->guest_mapped_mem.size = 0;
	/*state->vfio_dma_map.argsz = sizeof(state->vfio_dma_map);*/

	/* to map all the requested memory area of the guest probably will
	 * not suffice only one map request. With this structure we will
	 * keep trace of all the mappings required. */
	state->guest_mappings.num_mappings = 0;
	state->guest_mappings.mappings = g_malloc0(sizeof(struct guest_mapping) * MAPPING_BUFFER_SIZE);

#define IRQ
#ifdef IRQ
	FD_ZERO(&state->set_irq_efd);
	state->highest_irq_num = 0;
	state->efdnum_irqnum = g_hash_table_new_full(g_int_hash, g_int_equal,
								free, free);

	if(PL330_MAX_IRQS > state->device_info.num_irqs) {
		/*
		 * the device supports less irqs than the device tree says
		 * TODO error
		 * */
	}

	for(i = 0; i < PL330_MAX_IRQS; i++) {
		struct vfio_irq_info irq = { .argsz = sizeof(irq) };
		/*struct vfio_irq_set set = { .argsz = sizeof(set) };*/

		irq.index = i;

		ret = ioctl(state->device, VFIO_DEVICE_GET_IRQ_INFO, &irq);

		if (ret) {
        		error_setg(errp, "ioctl irq\n");
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

		}
	}
	// start irq handler
	start_irq_handler(state);
#endif

    	return;
}

static void pl330_vfio_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = pl330_vfio_realize;

    /*
     * TODO dc->vmsd = &vmstate_pl330_vfio;
     * TODO dc->reset = pl330_vfio_reset
     **/
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
 * guest driver and returns the guest hw address of the
 * destination specified for the DMA operation.
 *
 * This is useful to set the DMA mapping.
 * */
#define SAR			0
#define DAR 			2
#define DMAMOV_CMD		0xBC
#define DMAEND_CMD		0x0
static int get_dst_addr(uint32_t cmds_addr, hwaddr *src, hwaddr *dst) {
	// find the DMADST instruction
	int i;
	bool not_found = false;
	hwaddr _dst, _src;
	int len = PL330_BUFF_REQUEST_SIZE;
	uint8_t buffer[len];
	uint8_t *ptr = buffer;

	/*
	 * Since the buffer allocated by the guest driver with 
	 * the DMA controller instructions has to be a contiguous
	 * chunk of physical memory, we can map it in our address
	 * space.
	 *
	 * TODO handle size of the mapping
	 * */
	/*ptr = cpu_physical_memory_map((hwaddr)cmds_addr, &map_len, 0);*/
	dma_memory_read(&address_space_memory, (hwaddr)cmds_addr, ptr, len);
	if(ptr == NULL) {
		// error
		PL330_VFIO_DPRINTF("error while mapping guest mem to host\n");
		return -1;
	}


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

/* VFIO helper functions */
static int update_guest_mapped_mem(PL330VFIOState *state, hwaddr start_addr, hwaddr size)
{
	hwaddr old_size;
	hwaddr new_end;
	bool exit_mapping;
	bool update_inf = true, update_sup = true;

	// the first time there is no guest memory mapped so we always update
	if(state->guest_mapped_mem.addr || state->guest_mapped_mem.size) {
		update_inf = (state->guest_mapped_mem.addr > start_addr);
		update_sup = (state->guest_mapped_mem.addr
			+ state->guest_mapped_mem.size < start_addr + size);
	}

	old_size = state->guest_mapped_mem.size;

	if(update_inf || update_sup) {
		struct vfio_iommu_type1_dma_map update = { .argsz = sizeof(update) };
		hwaddr new_size, step_size = 0, total_mapped_size = 0, new_start;
		struct guest_mapping *guest_maps = NULL;
		void *ptr = NULL;

		new_start = (update_inf) ? start_addr : state->guest_mapped_mem.addr;
		new_end =  (update_sup) ? start_addr + size : state->guest_mapped_mem.addr
									+ old_size;
		new_size = new_end - new_start;

		// update previous qemu map
		if(old_size) {
			int num, i;
			struct vfio_iommu_type1_dma_unmap vfio_dma_unmap;

			guest_maps = state->guest_mappings.mappings;
			num = state->guest_mappings.num_mappings;
			for(i = 0; i < num; i++) {
				vfio_dma_unmap.iova = guest_maps[i].addr;
				vfio_dma_unmap.size = guest_maps[i].size;
				
				if(ioctl(state->container, VFIO_IOMMU_UNMAP_DMA, &vfio_dma_unmap)) {
					PL330_VFIO_DPRINTF("error while dma-unmapping\n");
					return -1;
				}

				cpu_physical_memory_unmap(guest_maps[i].guest_ptr,
						guest_maps[i].size, 0, guest_maps[i].size);

				state->guest_mappings.num_mappings--;
			}
			
		}

		/*
		 * The following request may non satisfy completely the requested size:
		 * in this case we need to do multiple mappings.
		 * */

		guest_maps = state->guest_mappings.mappings;
		exit_mapping = false;
		while(!exit_mapping && new_size) {
			step_size = new_size;

			ptr = cpu_physical_memory_map(new_start, &step_size, 0);
			if(ptr == NULL) {
				PL330_VFIO_DPRINTF("error while creating qemu-map\n");
				return -1;
			}

			guest_maps[state->guest_mappings.num_mappings].guest_ptr = ptr;
			guest_maps[state->guest_mappings.num_mappings].addr = new_start;
			guest_maps[state->guest_mappings.num_mappings].size = step_size;

			update.vaddr = (uintptr_t)ptr;
			update.flags = VFIO_DEF_MASK;
			update.iova = new_start;
			update.size = step_size;

			PL330_VFIO_DPRINTF("dma map: vaddr: 0x%llx, iova: 0x%llx, size: %llu\
					, size_2: %llu\n", update.vaddr, update.iova, update.size, new_size);
			if(ioctl(state->container, VFIO_IOMMU_MAP_DMA, &update)) {
				PL330_VFIO_DPRINTF("error while updating dma-map\n");
				return -1;
			}

			// update mapped state
			state->guest_mappings.num_mappings++;
			if(new_size >= step_size) {
				new_size -= step_size;
			}
			else {
				exit_mapping = true;
			}
			total_mapped_size += step_size;
			new_start += step_size;
		}
		state->guest_mapped_mem.addr = guest_maps[0].addr;
		state->guest_mapped_mem.size = total_mapped_size;
	} else {
		PL330_VFIO_DPRINTF("no update necessary\n");
	}

	return 0;
}

static void *get_pl330_reg_ptr(PL330VFIOState *state)
{
	void *ptr = NULL;
	int ret;
	int container, group, device;
	// group id
	const char *group_str = VFIO_GROUP;
	// device id
	const char *device_str = VFIO_DEVICE;

	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };

	container = open(VFIO_CONTAINER, O_RDWR);
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
		/*
		 * Create a mask with all triggered interrupts, and then clear them.
		 * It could be done with only one g_hash_table_foreach TODO, but for
		 * now we keep in this way.
		 * */
		g_hash_table_foreach(state->efdnum_irqnum, qemu_trigger_irq,
							state);
		restore_fdset(state);
	}

	return NULL;
}

int start_irq_handler(PL330VFIOState *state)
{
	int ret;

	ret = pthread_create(&state->irq_handler, NULL, irq_handler_func, state);
	
	if(ret) {
		PL330_VFIO_DPRINTF("error while creating thread\n");
		return -1;
	}
	
	return 0;
}


void pl330_vfio_legacy_init(qemu_irq *base_irq)
{
    DeviceState *dev;
    SysBusDevice *bus;

    dev = qdev_create(NULL, TYPE_PL330_VFIO);
    qdev_init_nofail(dev);
    bus = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(bus, 0, 0x7ffb0000);
	
    int i;
    for(i = 0; i < PL330_MAX_IRQS; i++) {
    	sysbus_connect_irq(bus, 0, base_irq[i]);
    }
}

static void vfio_irqfd_init(int device, unsigned int index, int fd)
{
	struct vfio_irq_set *irq_set;
	int32_t *pfd;
	int ret, argsz;

	argsz = sizeof(*irq_set) + sizeof(*pfd);
	irq_set = malloc(argsz);

	if (!irq_set) {
		PL330_VFIO_DPRINTF("Failure in allocating memory\n");
		// TODO proper exit
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
		PL330_VFIO_DPRINTF("Failure IRQ \n");
		return;
	}
}


type_init(pl330_vfio_register_types)

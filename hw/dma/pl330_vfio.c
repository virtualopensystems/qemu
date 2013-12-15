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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>

#include "sysemu/dma.h"

/*#define VENDOR_ID_PL330_VFIO something*/
#define VFIO_DMA_MAP_FLAG_EXEC (1 << 2)        /* executable from device */

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

/* device specific configuration */
#define PL330_VFIO_MEMSIZE		0x1000
#define VFIO_FAIL			((void *)-1)

#define PL330_MAX_CHANNELS		8

typedef struct PL330VFIOState {
	SysBusDevice parent_obj;

    	/* Registers memory */
    	MemoryRegion mmio;
    	MemoryRegion regs_mem;

	/* 32bit registers */
	void *regs;	

	struct debug_ins_request *pending_request;

	// VFIO
	int container;
} PL330VFIOState;

/*
 * This structure represent a physical memory area of the guest
 * which has to be DMA mapped
 * */
typedef struct guest_phys_mem_area{
	hwaddr addr;
	hwaddr size;
} guest_phys_area;

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

	void *guest_ptr;
};

static void *get_pl330_reg_ptr(PL330VFIOState *state);
static int get_dst_addr(uint32_t cmds_addr, hwaddr *src, hwaddr *dst);

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


#define DBGCMD			0xD04
#define DBGINST0		0xD08
#define DBGINST1		0xD0C
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
	 *
	 * */
	struct debug_ins_request *req = state->pending_request;
	switch(addr) {
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
			PL330_VFIO_DPRINTF("ready to submit, hw addr: 0x%x\n", req->dbginst1);
		}
		else {
			// error
		}
		break;
	case DBGCMD:
		if (req->to_submit) {
			int ret1;
			hwaddr src = 0, dst = 0;
			uint32_t page_size = getpagesize();

			if(get_dst_addr(req->dbginst1, &src, &dst)) {
				PL330_VFIO_DPRINTF("error during write\n");
			}

			PL330_VFIO_DPRINTF("src: 0x%llx, dst: 0x%llx, ins: 0x%x\n",
					src, dst, req->dbginst1);

			/* memory areas of the guest that we have to map */
			guest_phys_area src_guest_area = {src, 4};
			guest_phys_area dst_guest_area = {dst, 4};
			guest_phys_area ins_guest_area = {req->dbginst1, 100};

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

			/*
			 * we first map the desired guest memory area in the qemu addr
			 * space, then we DMA map through VFIO
			 * */
			req->guest_ptr = cpu_physical_memory_map(start_addr, &mapped_size, 1);

			if(req->guest_ptr == NULL) {
				PL330_VFIO_DPRINTF("error mapping guest memory\n");
			}
			else {
				PL330_VFIO_DPRINTF("mappen len: %lluB\n", mapped_size);
				PL330_VFIO_DPRINTF("ptr: 0x%x\n", (uintptr_t)req->guest_ptr);
				// these two outputs should be the same...
				PL330_VFIO_DPRINTF("src val: 0x%x\n", *((uint32_t *)(req->guest_ptr +
									src - start_addr)));
				PL330_VFIO_DPRINTF("dst val: 0x%x\n", *((uint32_t *)(req->guest_ptr +
									dst - start_addr)));
				int buf = 0;
				dma_memory_read(&address_space_memory, src, &buf, 4);
				PL330_VFIO_DPRINTF("src val: 0x%x\n", buf);
			}

			struct vfio_iommu_type1_dma_map dma_map = { .argsz = sizeof(dma_map) };

			dma_map.vaddr = (uint64_t)req->guest_ptr;
			dma_map.size = mapped_size;
			dma_map.iova = start_addr;
			dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
							/*| VFIO_DMA_MAP_FLAG_EXEC;*/

			ret1 = ioctl(state->container, VFIO_IOMMU_MAP_DMA, &dma_map);

			if(ret1) PL330_VFIO_DPRINTF("error while dma-mapping-1\n");

			if(ret1) {
				return;
			}

			// flush the request to the real device
			*((int *)(state->regs + DBGINST0)) = req->dbginst0;
			*((int *)(state->regs + DBGINST1)) = req->dbginst1;
			*((int *)(state->regs + DBGCMD)) = (uint32_t)data;
			// clear pending request
			*req = debug_ins_req_blank;

			int j = 0;
			for (; j < 9999999; j++) {
				continue;
			}
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

/*static void add_regsmem_from_ptr(PL330VFIOState *state, void *mem_ptr)
{
	memory_region_init_ram_ptr(&state->regs_mem, OBJECT(state),
			"dma-vfio.regs", PL330_VFIO_MEMSIZE, mem_ptr);
	vmstate_register_ram(&state->regs_mem, DEVICE(state));
	memory_region_add_subregion(&state->mmio, 0, &state->regs_mem);
}*/

static void pl330_vfio_realize(DeviceState *dev, Error **errp)
{
	void *regs = NULL;
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
    	//add_regsmem_from_ptr(state, regs);
    	sysbus_init_mmio(sys_dev, &state->mmio);

    	/* init irq */
    	/*sysbus_init_irq(sys_dev, &state->irq);*/

	state->pending_request = g_malloc0(sizeof(struct debug_ins_request));

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
	int len = 100;
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
		PL330_VFIO_DPRINTF("src address found\n");
	} else {
		PL330_VFIO_DPRINTF("src address not found\n");
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
		PL330_VFIO_DPRINTF("dst address found\n");
	} else {
		PL330_VFIO_DPRINTF("dst address not found\n");
		return -1;
	}

	*dst = _dst;
	*src = _src;

	return 0;
}

/* VFIO helper functions */
static void *get_pl330_reg_ptr(PL330VFIOState *state)
{
	void *ptr = NULL;
	int ret;
	int container, group, device;
	// group id
	const char *group_str = "/dev/vfio/0";
	// device id
	const char *device_str = "2c0a0000.dma";

	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };

	container = open("/dev/vfio/vfio", O_RDWR);

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
	PL330_VFIO_DPRINTF("=== VFIO device file descriptor %d ===\n", device);

	/* Test and setup the device */
	ret = ioctl(device, VFIO_DEVICE_GET_INFO, &device_info);

	if(ret) {
		PL330_VFIO_DPRINTF("Could not get VFIO device\n");
		ptr = VFIO_FAIL;
		goto out;
	}

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

void pl330_vfio_legacy_init(void)
{
    DeviceState *dev;
    SysBusDevice *bus;

    dev = qdev_create(NULL, TYPE_PL330_VFIO);
    qdev_init_nofail(dev);
    bus = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(bus, 0, 0x7ffb0000);
    /*sysbus_connect_irq(bus, 0, irq);*/
}

type_init(pl330_vfio_register_types)

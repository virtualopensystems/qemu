/*
 * ARM mach-virt emulation
 *
 * Copyright (c) 2013 Linaro
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Emulate a virtual board compatible with arch/arm/mach-virt/virt.c in the
 * linux kernel source.
 */

#include "hw/sysbus.h"
#include "hw/arm/arm.h"
#include "hw/arm/primecell.h"
#include "hw/devices.h"
#include "net/net.h"
#include "sysemu/device_tree.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"
#include "libfdt_env.h"

#define GIC_FDT_IRQ_NUM_CELLS 3

#define GIC_FDT_IRQ_TYPE_SPI 0
#define GIC_FDT_IRQ_TYPE_PPI 1

#define GIC_FDT_IRQ_FLAGS_EDGE_LO_HI 1
#define GIC_FDT_IRQ_FLAGS_EDGE_HI_LO 2
#define GIC_FDT_IRQ_FLAGS_LEVEL_HI 4
#define GIC_FDT_IRQ_FLAGS_LEVEL_LO 8

#define GIC_FDT_IRQ_PPI_CPU_SHIFT 8
#define GIC_FDT_IRQ_PPI_CPU_MASK (0xff << GIC_FDT_IRQ_PPI_CPU_SHIFT)

#define CPU_NAME_MAX_LEN 16

#define MEM_BASE 0
#define MAX_MEM 0xff800000
#define IO_BASE 0xfff00000
#define IO_LEN 0x000f0000

#if defined(TARGET_AARCH64)
#define DEFAULT_CPU_MODEL "cortex-a57"
#elif defined(TARGET_ARM)
#define DEFAULT_CPU_MODEL "cortex-a15"
#endif

struct machine_info {
    const char cpu_model[CPU_NAME_MAX_LEN];
    const char *cpu_compatible;
    const char *qdevname;
    uint64_t mem_base;
    uint64_t max_mem;
    uint64_t io_base;
    uint64_t io_len;
    /* offsets and sizes of gic regions */
    struct {
        uint32_t dist_base;
        uint32_t dist_size;
        uint32_t cpui_base;
        uint32_t cpui_size;
        uint32_t total_size;
        const char *compatible;
    } gic_info;
    char *gic;
};

static struct machine_info machines[] = {
#if defined(TARGET_AARCH64)
    {
        .cpu_model = "cortex-a57",
        .cpu_compatible = "arm,arm-v8",
        .qdevname = "a57mpcore_priv",
        .mem_base = MEM_BASE,
        .max_mem = MAX_MEM,
        .io_base = IO_BASE,
        .io_len = IO_LEN,
        .gic_info = {0x01000, 0x1000, 0x02000, 0x1000, 0x8000,
		"arm,cortex-a15-gic"},
    },
#elif defined(TARGET_ARM)
    {
        .cpu_model = "cortex-a15",
        .cpu_compatible = "arm,cortex-a15",
        .qdevname = "a15mpcore_priv",
        .mem_base = MEM_BASE,
        .max_mem = MAX_MEM,
        .io_base = IO_BASE,
        .io_len = IO_LEN,
        .gic_info = {0x01000, 0x1000, 0x02000, 0x1000, 0x8000,
		"arm,cortex-a15-gic"},
    },
    {
        .cpu_model = "cortex-a9",
        .cpu_compatible = "arm,cortex-a9",
        .qdevname = "a9mpcore_priv",
        .mem_base = MEM_BASE,
        .max_mem = MAX_MEM,
        .io_base = IO_BASE,
        .io_len = IO_LEN,
        .gic_info = {0x01000, 0x1000, 0x0100, 0x0100, 0x2000,
		"arm,cortex-a9-gic"},
    },
#endif
    {
        .cpu_model = "",
    },
};

static struct machine_info *find_machine_info(const char *cpu)
{
    struct machine_info *mi = machines;

    while (mi->cpu_model[0]) {
        if (strncmp(cpu, mi->cpu_model, sizeof(mi->cpu_model)) == 0) {
            return mi;
        }
        mi++;
    }
    return NULL;
}

static void *virt_fdt;
static int virt_fdt_size;

static void *initial_fdt(struct machine_info *mi)
{
    void *fdt = create_device_tree(&virt_fdt_size);
    char compatible_sb[] = "simple-bus\0arm,amba-bus";

    if (fdt == NULL) {
        return NULL;
    }

    /* Header */
    qemu_devtree_setprop_string(fdt, "/", "compatible", "linux,dummy-virt");
    qemu_devtree_setprop_cell(fdt, "/", "#address-cells", 0x2);
    qemu_devtree_setprop_cell(fdt, "/", "#size-cells", 0x2);

    /*
     * /chosen and /memory nodes must exist for load_dtb
     * to fill in neccessary properties later
     */
    qemu_devtree_add_subnode(fdt, "/chosen");
    qemu_devtree_add_subnode(fdt, "/memory");
    qemu_devtree_setprop_string(fdt, "/memory", "device_type", "memory");

    /*
     * Fixed soc properties
     */
    qemu_devtree_add_subnode(fdt, "/soc");
    qemu_devtree_setprop(fdt, "/soc", "compatible", compatible_sb,
            sizeof(compatible_sb));
    qemu_devtree_setprop_cell(fdt, "/soc", "#address-cells", 0x1);
    qemu_devtree_setprop_cell(fdt, "/soc", "#size-cells", 0x1);
    qemu_devtree_setprop_cells(fdt, "/soc", "ranges", mi->io_base, 0x0,
            mi->io_base, mi->io_len);
    qemu_devtree_setprop_cell(fdt, "/soc", "#interrupt-cells", 0x1);

    /* No PSCI for TCG yet */
#ifdef CONFIG_KVM
    if (kvm_enabled()) {
        qemu_devtree_add_subnode(fdt, "/psci");
        qemu_devtree_setprop_string(fdt, "/psci", "compatible", "arm,psci");
        qemu_devtree_setprop_string(fdt, "/psci", "method", "hvc");
        qemu_devtree_setprop_cell(fdt, "/psci", "cpu_suspend",
                KVM_PSCI_FN_CPU_SUSPEND);
        qemu_devtree_setprop_cell(fdt, "/psci", "cpu_off", KVM_PSCI_FN_CPU_OFF);
        qemu_devtree_setprop_cell(fdt, "/psci", "cpu_on", KVM_PSCI_FN_CPU_ON);
        qemu_devtree_setprop_cell(fdt, "/psci", "migrate", KVM_PSCI_FN_MIGRATE);
    }
#endif
    return  fdt;
}

static void fdt_add_timer_nodes(void *fdt, int smp_cpus)
{
    uint32_t cpu_mask =
        (((1 << smp_cpus) - 1) << GIC_FDT_IRQ_PPI_CPU_SHIFT)
                        & GIC_FDT_IRQ_PPI_CPU_MASK;
    cpu_mask = 0xf00;
    uint32_t irq_prop[] = {
        cpu_to_fdt32(GIC_FDT_IRQ_TYPE_PPI),
        cpu_to_fdt32(13),
        cpu_to_fdt32(cpu_mask | GIC_FDT_IRQ_FLAGS_EDGE_LO_HI),

        cpu_to_fdt32(GIC_FDT_IRQ_TYPE_PPI),
        cpu_to_fdt32(14),
        cpu_to_fdt32(cpu_mask | GIC_FDT_IRQ_FLAGS_EDGE_LO_HI),

        cpu_to_fdt32(GIC_FDT_IRQ_TYPE_PPI),
        cpu_to_fdt32(11),
        cpu_to_fdt32(cpu_mask | GIC_FDT_IRQ_FLAGS_EDGE_LO_HI),

        cpu_to_fdt32(GIC_FDT_IRQ_TYPE_PPI),
        cpu_to_fdt32(10),
        cpu_to_fdt32(cpu_mask | GIC_FDT_IRQ_FLAGS_EDGE_LO_HI),
    };

    qemu_devtree_add_subnode(fdt, "/timer");
    qemu_devtree_setprop_string(fdt, "/timer", "compatible", "arm,armv7-timer");
    qemu_devtree_setprop(fdt, "/timer", "interrupts", irq_prop,
            sizeof(irq_prop));
}

static void fdt_add_cpu_nodes(void *fdt, struct machine_info *mi, int smp_cpus)
{
    int cpu;

    qemu_devtree_add_subnode(fdt, "/cpus");
    qemu_devtree_setprop_cell(fdt, "/cpus", "#address-cells", 0x1);
    qemu_devtree_setprop_cell(fdt, "/cpus", "#size-cells", 0x0);

    for (cpu = 0; cpu < smp_cpus; ++cpu) {
        char cpu_name[CPU_NAME_MAX_LEN];

        snprintf(cpu_name, CPU_NAME_MAX_LEN, "/cpus/cpu@%d", cpu);

        qemu_devtree_add_subnode(fdt, cpu_name);
        qemu_devtree_setprop_string(fdt, cpu_name, "device_type", "cpu");
        qemu_devtree_setprop_string(fdt, cpu_name, "compatible",
            mi->cpu_compatible);

        if (smp_cpus > 1) {
            qemu_devtree_setprop_string(fdt, cpu_name, "enable-method", "psci");
        }

        qemu_devtree_setprop_cell(fdt, cpu_name, "reg", cpu);
    }
}

static void add_interrupt_map(void *fdt, const char *soc, uint32_t gic,
		int nirqs)
{
    int i, irq;
    int len;
    uint32_t *map;

    qemu_devtree_setprop_cell(fdt, soc, "#interrupt-cells", 0x1);
    qemu_devtree_setprop_cells(fdt, soc, "interrupt-map-mask", 0, 63);

    len = nirqs * 6 * sizeof(uint32_t);
    map = g_malloc(len);

    for (i = 0, irq = 0; irq < nirqs; irq++) {
        map[i++] = cpu_to_be32(0x0);
        map[i++] = cpu_to_be32(irq);
        map[i++] = cpu_to_be32(gic);
        map[i++] = cpu_to_be32(0x0);
        map[i++] = cpu_to_be32(irq);
        map[i++] = cpu_to_be32(4);
    }
    qemu_devtree_setprop(fdt, soc, "interrupt-map", map, len);
    g_free(map);
}

static void fdt_add_gic_node(void *fdt, struct machine_info *mi)
{
    uint32_t gic_phandle;
    uint64_t reg_prop[4];

    reg_prop[0] = cpu_to_fdt64(mi->gic_info.dist_base + mi->io_base);
    reg_prop[1] = cpu_to_fdt64(mi->gic_info.dist_size);
    reg_prop[2] = cpu_to_fdt64(mi->gic_info.cpui_base + mi->io_base);
    reg_prop[3] = cpu_to_fdt64(mi->gic_info.cpui_size);

    mi->io_base += mi->gic_info.total_size;

    gic_phandle = qemu_devtree_alloc_phandle(fdt);
    qemu_devtree_setprop_cell(fdt, "/", "interrupt-parent", gic_phandle);

    qemu_devtree_add_subnode(fdt, "/intc");
    qemu_devtree_setprop_string(fdt, "/intc", "compatible",
            mi->gic_info.compatible);
    qemu_devtree_setprop_cell(fdt, "/intc", "#interrupt-cells",
            GIC_FDT_IRQ_NUM_CELLS);
    qemu_devtree_setprop(fdt, "/intc", "interrupt-controller", NULL, 0);
    qemu_devtree_setprop(fdt, "/intc", "reg", reg_prop, sizeof(reg_prop));
    qemu_devtree_setprop_cell(fdt, "/intc", "phandle", gic_phandle);
    add_interrupt_map(fdt, "/soc", gic_phandle, 43);
}

static void fdt_add_soc_nodes(void *fdt, struct machine_info *mi, qemu_irq *pic)
{
    uint32_t clock_phandle;
    char compatible_uart[] = "arm,pl011\0arm,primecell";
    char compatible_timer[] = "arm,sp804\0arm,primecell";
    char clock_names_uart[] = "uartclk\0apb_pclk";
    char clock_names_timer[] = "timerclk\0apb_pclk";
    uint32_t base;
    uint32_t len;
    int irq;

    clock_phandle = qemu_devtree_alloc_phandle(fdt);
    qemu_devtree_add_subnode(fdt, "/soc/clock");
    qemu_devtree_setprop_string(fdt, "/soc/clock", "compatible", "fixed-clock");
    qemu_devtree_setprop_cell(fdt, "/soc/clock", "#clock-cells", 0x0);
    qemu_devtree_setprop_cell(fdt, "/soc/clock", "clock-frequency", 24000000);
    qemu_devtree_setprop_string(fdt, "/soc/clock", "clock-output-names",
            "clk24mhz");
    qemu_devtree_setprop_cell(fdt, "/soc/clock", "phandle", clock_phandle);

    len = 0x1000;
    base = mi->io_base;
    mi->io_base += len;
    irq = 5;
    sysbus_create_simple("pl011", base, pic[irq]);
    qemu_devtree_add_subnode(fdt, "/soc/uart");
    qemu_devtree_setprop(fdt, "/soc/uart", "compatible", compatible_uart,
            sizeof(compatible_uart));
    qemu_devtree_setprop_cells(fdt, "/soc/uart", "reg", base, len);
    qemu_devtree_setprop_cell(fdt, "/soc/uart", "interrupts", irq);
    qemu_devtree_setprop_cells(fdt, "/soc/uart", "clocks", clock_phandle,
            clock_phandle);
    qemu_devtree_setprop(fdt, "/soc/uart", "clock-names", clock_names_uart,
            sizeof(clock_names_uart));

    len = 0x1000;
    base = mi->io_base;
    mi->io_base += len;
    irq = 2;
    sysbus_create_simple("sp804", base, pic[irq]);
    qemu_devtree_add_subnode(fdt, "/soc/timer");
    qemu_devtree_setprop(fdt, "/soc/timer", "compatible", compatible_timer,
            sizeof(compatible_timer));
    qemu_devtree_setprop_cells(fdt, "/soc/timer", "reg", base, len);
    qemu_devtree_setprop_cell(fdt, "/soc/timer", "interrupts", irq);
    qemu_devtree_setprop_cells(fdt, "/soc/timer", "clocks", clock_phandle,
            clock_phandle);
    qemu_devtree_setprop(fdt, "/soc/timer", "clock-names", clock_names_timer,
            sizeof(clock_names_timer));
}

static void *machvirt_dtb(hwaddr addr, const struct arm_boot_info *binfo,
        int *fdt_size)
{
    *fdt_size = virt_fdt_size;
    return virt_fdt;
}

static struct arm_boot_info machvirt_binfo;

static void machvirt_init(QEMUMachineInitArgs *args)
{
    qemu_irq pic[64];
    MemoryRegion *sysmem = get_system_memory();
    int n;
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    qemu_irq cpu_irq[4];
    DeviceState *dev;
    SysBusDevice *busdev;
    const char *cpu_model = args->cpu_model;
    struct machine_info *mi;

    if (!cpu_model) {
        cpu_model = DEFAULT_CPU_MODEL;
    }

    mi = find_machine_info(cpu_model);

    if (!mi) {
        hw_error("No machine info for cpu %s\n", cpu_model);
        exit(1);
    }

    /*
     * Only supported method of starting secondary CPUs is PSCI and
     * PSCI is not yet supported with TCG so limit smp_cpus to 1
     * if not kvm.
     */
    if (!kvm_enabled() && smp_cpus > 1) {
        hw_error("Multiple cpus only supported with kvm\n");
        exit(1);
    }

    if (ram_size > mi->max_mem) {
            fprintf(stderr, "mach-virt: cannot model more than 30GB RAM\n");
            exit(1);
    }

    virt_fdt = initial_fdt(mi);
    fdt_add_timer_nodes(virt_fdt, smp_cpus);

    for (n = 0; n < smp_cpus; n++) {
        ARMCPU *cpu;
        qemu_irq *irqp;

        cpu = cpu_arm_init(cpu_model);
        if (!cpu) {
            fprintf(stderr, "Unable to find CPU definition %s\n", cpu_model);
            exit(1);
        }
        irqp = arm_pic_init_cpu(cpu);
        cpu_irq[n] = irqp[ARM_PIC_CPU_IRQ];
    }
    fdt_add_cpu_nodes(virt_fdt, mi, smp_cpus);

    memory_region_init_ram(ram, "mach-virt.ram", ram_size);
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(sysmem, mi->mem_base, ram);

    dev = qdev_create(NULL, mi->qdevname);
    qdev_prop_set_uint32(dev, "num-cpu", smp_cpus);
    qdev_init_nofail(dev);
    busdev = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(busdev, 0, mi->io_base);
    fdt_add_gic_node(virt_fdt, mi);
    for (n = 0; n < smp_cpus; n++) {
        sysbus_connect_irq(busdev, n, cpu_irq[n]);
    }

    for (n = 0; n < 64; n++) {
        pic[n] = qdev_get_gpio_in(dev, n);
    }

    /*
     * Not completely virtual yet, add some soc io nodes
     */
    fdt_add_soc_nodes(virt_fdt, mi, pic);

    machvirt_binfo.ram_size = args->ram_size;
    machvirt_binfo.kernel_filename = args->kernel_filename;
    machvirt_binfo.kernel_cmdline = args->kernel_cmdline;
    machvirt_binfo.initrd_filename = args->initrd_filename;
    machvirt_binfo.nb_cpus = smp_cpus;
    machvirt_binfo.board_id = -1;
    machvirt_binfo.loader_start = mi->mem_base;
    machvirt_binfo.get_dtb = machvirt_dtb;
    arm_load_kernel(arm_env_get_cpu(first_cpu), &machvirt_binfo);
}

static QEMUMachine machvirt_a15_machine = {
    .name = "machvirt",
    .desc = "ARM Virtual Machine",
    .init = machvirt_init,
    .max_cpus = 4,
    DEFAULT_MACHINE_OPTIONS,
};

static void machvirt_machine_init(void)
{
    qemu_register_machine(&machvirt_a15_machine);
}

machine_init(machvirt_machine_init);

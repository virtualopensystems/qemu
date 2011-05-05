/*
 *  QEMU model of the Milkymist programmable FPU.
 *
 *  Copyright (c) 2010 Michael Walle <michael@walle.cc>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Specification available at:
 *   http://www.milkymist.org/socdoc/pfpu.pdf
 *
 */

#include "hw.h"
#include "sysbus.h"
#include "trace.h"
#include "qemu-log.h"
#include "qemu-error.h"
#include <math.h>

/* #define TRACE_EXEC */

#ifdef TRACE_EXEC
#    define D_EXEC(x) x
#else
#    define D_EXEC(x)
#endif

enum {
    R_CTL = 0,
    R_MESHBASE,
    R_HMESHLAST,
    R_VMESHLAST,
    R_CODEPAGE,
    R_VERTICES,
    R_COLLISIONS,
    R_STRAYWRITES,
    R_LASTDMA,
    R_PC,
    R_DREGBASE,
    R_CODEBASE,
    R_MAX
};

enum {
    CTL_START_BUSY = (1<<0),
};

enum {
    OP_NOP = 0,
    OP_FADD,
    OP_FSUB,
    OP_FMUL,
    OP_FABS,
    OP_F2I,
    OP_I2F,
    OP_VECTOUT,
    OP_SIN,
    OP_COS,
    OP_ABOVE,
    OP_EQUAL,
    OP_COPY,
    OP_IF,
    OP_TSIGN,
    OP_QUAKE,
};

enum {
    GPR_X = 0,
    GPR_Y = 1,
    GPR_FLAGS = 2,
};

enum {
    LATENCY_FADD = 5,
    LATENCY_FSUB = 5,
    LATENCY_FMUL = 7,
    LATENCY_FABS = 2,
    LATENCY_F2I = 2,
    LATENCY_I2F = 3,
    LATENCY_VECTOUT = 0,
    LATENCY_SIN = 4,
    LATENCY_COS = 4,
    LATENCY_ABOVE = 2,
    LATENCY_EQUAL = 2,
    LATENCY_COPY = 2,
    LATENCY_IF = 2,
    LATENCY_TSIGN = 2,
    LATENCY_QUAKE = 2,
    MAX_LATENCY = 7
};

#define GPR_BEGIN       0x100
#define GPR_END         0x17f
#define MICROCODE_BEGIN 0x200
#define MICROCODE_END   0x3ff
#define MICROCODE_WORDS 2048

#define REINTERPRET_CAST(type, val) (*((type *)&(val)))

#ifdef TRACE_EXEC
static const char *opcode_to_str[] = {
    "NOP", "FADD", "FSUB", "FMUL", "FABS", "F2I", "I2F", "VECTOUT",
    "SIN", "COS", "ABOVE", "EQUAL", "COPY", "IF", "TSIGN", "QUAKE",
};
#endif

struct MilkymistPFPUState {
    SysBusDevice busdev;
    CharDriverState *chr;
    qemu_irq irq;

    uint32_t regs[R_MAX];
    uint32_t gp_regs[128];
    uint32_t microcode[MICROCODE_WORDS];

    int output_queue_pos;
    uint32_t output_queue[MAX_LATENCY];
};
typedef struct MilkymistPFPUState MilkymistPFPUState;

static inline target_phys_addr_t
get_dma_address(uint32_t base, uint32_t x, uint32_t y)
{
    return base + 8 * (128 * y + x);
}

static inline void
output_queue_insert(MilkymistPFPUState *s, uint32_t val, int pos)
{
    s->output_queue[(s->output_queue_pos + pos) % MAX_LATENCY] = val;
}

static inline uint32_t
output_queue_remove(MilkymistPFPUState *s)
{
    return s->output_queue[s->output_queue_pos];
}

static inline void
output_queue_advance(MilkymistPFPUState *s)
{
    s->output_queue[s->output_queue_pos] = 0;
    s->output_queue_pos = (s->output_queue_pos + 1) % MAX_LATENCY;
}

static int pfpu_decode_insn(MilkymistPFPUState *s)
{
    uint32_t pc = s->regs[R_PC];
    uint32_t insn = s->microcode[pc];
    uint32_t reg_a = (insn >> 18) & 0x7f;
    uint32_t reg_b = (insn >> 11) & 0x7f;
    uint32_t op = (insn >> 7) & 0xf;
    uint32_t reg_d = insn & 0x7f;
    uint32_t r = 0;
    int latency = 0;

    switch (op) {
    case OP_NOP:
        break;
    case OP_FADD:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        float b = REINTERPRET_CAST(float, s->gp_regs[reg_b]);
        float t = a + b;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_FADD;
        D_EXEC(qemu_log("ADD a=%f b=%f t=%f, r=%08x\n", a, b, t, r));
    } break;
    case OP_FSUB:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        float b = REINTERPRET_CAST(float, s->gp_regs[reg_b]);
        float t = a - b;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_FSUB;
        D_EXEC(qemu_log("SUB a=%f b=%f t=%f, r=%08x\n", a, b, t, r));
    } break;
    case OP_FMUL:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        float b = REINTERPRET_CAST(float, s->gp_regs[reg_b]);
        float t = a * b;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_FMUL;
        D_EXEC(qemu_log("MUL a=%f b=%f t=%f, r=%08x\n", a, b, t, r));
    } break;
    case OP_FABS:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        float t = fabsf(a);
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_FABS;
        D_EXEC(qemu_log("ABS a=%f t=%f, r=%08x\n", a, t, r));
    } break;
    case OP_F2I:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        int32_t t = a;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_F2I;
        D_EXEC(qemu_log("F2I a=%f t=%d, r=%08x\n", a, t, r));
    } break;
    case OP_I2F:
    {
        int32_t a = REINTERPRET_CAST(int32_t, s->gp_regs[reg_a]);
        float t = a;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_I2F;
        D_EXEC(qemu_log("I2F a=%08x t=%f, r=%08x\n", a, t, r));
    } break;
    case OP_VECTOUT:
    {
        uint32_t a = cpu_to_be32(s->gp_regs[reg_a]);
        uint32_t b = cpu_to_be32(s->gp_regs[reg_b]);
        target_phys_addr_t dma_ptr =
            get_dma_address(s->regs[R_MESHBASE],
                    s->gp_regs[GPR_X], s->gp_regs[GPR_Y]);
        cpu_physical_memory_write(dma_ptr, (uint8_t *)&a, 4);
        cpu_physical_memory_write(dma_ptr + 4, (uint8_t *)&b, 4);
        s->regs[R_LASTDMA] = dma_ptr + 4;
        D_EXEC(qemu_log("VECTOUT a=%08x b=%08x dma=%08x\n", a, b, dma_ptr));
        trace_milkymist_pfpu_vectout(a, b, dma_ptr);
    } break;
    case OP_SIN:
    {
        int32_t a = REINTERPRET_CAST(int32_t, s->gp_regs[reg_a]);
        float t = sinf(a * (1.0f / (M_PI * 4096.0f)));
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_SIN;
        D_EXEC(qemu_log("SIN a=%d t=%f, r=%08x\n", a, t, r));
    } break;
    case OP_COS:
    {
        int32_t a = REINTERPRET_CAST(int32_t, s->gp_regs[reg_a]);
        float t = cosf(a * (1.0f / (M_PI * 4096.0f)));
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_COS;
        D_EXEC(qemu_log("COS a=%d t=%f, r=%08x\n", a, t, r));
    } break;
    case OP_ABOVE:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        float b = REINTERPRET_CAST(float, s->gp_regs[reg_b]);
        float t = (a > b) ? 1.0f : 0.0f;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_ABOVE;
        D_EXEC(qemu_log("ABOVE a=%f b=%f t=%f, r=%08x\n", a, b, t, r));
    } break;
    case OP_EQUAL:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        float b = REINTERPRET_CAST(float, s->gp_regs[reg_b]);
        float t = (a == b) ? 1.0f : 0.0f;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_EQUAL;
        D_EXEC(qemu_log("EQUAL a=%f b=%f t=%f, r=%08x\n", a, b, t, r));
    } break;
    case OP_COPY:
    {
        r = s->gp_regs[reg_a];
        latency = LATENCY_COPY;
        D_EXEC(qemu_log("COPY"));
    } break;
    case OP_IF:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        float b = REINTERPRET_CAST(float, s->gp_regs[reg_b]);
        uint32_t f = s->gp_regs[GPR_FLAGS];
        float t = (f != 0) ? a : b;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_IF;
        D_EXEC(qemu_log("IF f=%u a=%f b=%f t=%f, r=%08x\n", f, a, b, t, r));
    } break;
    case OP_TSIGN:
    {
        float a = REINTERPRET_CAST(float, s->gp_regs[reg_a]);
        float b = REINTERPRET_CAST(float, s->gp_regs[reg_b]);
        float t = (b < 0) ? -a : a;
        r = REINTERPRET_CAST(uint32_t, t);
        latency = LATENCY_TSIGN;
        D_EXEC(qemu_log("TSIGN a=%f b=%f t=%f, r=%08x\n", a, b, t, r));
    } break;
    case OP_QUAKE:
    {
        uint32_t a = s->gp_regs[reg_a];
        r = 0x5f3759df - (a >> 1);
        latency = LATENCY_QUAKE;
        D_EXEC(qemu_log("QUAKE a=%d r=%08x\n", a, r));
    } break;

    default:
        error_report("milkymist_pfpu: unknown opcode %d\n", op);
        break;
    }

    if (!reg_d) {
        D_EXEC(qemu_log("%04d %8s R%03d, R%03d <L=%d, E=%04d>\n",
                    s->regs[R_PC], opcode_to_str[op], reg_a, reg_b, latency,
                    s->regs[R_PC] + latency));
    } else {
        D_EXEC(qemu_log("%04d %8s R%03d, R%03d <L=%d, E=%04d> -> R%03d\n",
                    s->regs[R_PC], opcode_to_str[op], reg_a, reg_b, latency,
                    s->regs[R_PC] + latency, reg_d));
    }

    if (op == OP_VECTOUT) {
        return 0;
    }

    /* store output for this cycle */
    if (reg_d) {
        uint32_t val = output_queue_remove(s);
        D_EXEC(qemu_log("R%03d <- 0x%08x\n", reg_d, val));
        s->gp_regs[reg_d] = val;
    }

    output_queue_advance(s);

    /* store op output */
    if (op != OP_NOP) {
        output_queue_insert(s, r, latency-1);
    }

    /* advance PC */
    s->regs[R_PC]++;

    return 1;
};

static void pfpu_start(MilkymistPFPUState *s)
{
    int x, y;
    int i;

    for (y = 0; y <= s->regs[R_VMESHLAST]; y++) {
        for (x = 0; x <= s->regs[R_HMESHLAST]; x++) {
            D_EXEC(qemu_log("\nprocessing x=%d y=%d\n", x, y));

            /* set current position */
            s->gp_regs[GPR_X] = x;
            s->gp_regs[GPR_Y] = y;

            /* run microcode on this position */
            i = 0;
            while (pfpu_decode_insn(s)) {
                /* decode at most MICROCODE_WORDS instructions */
                if (i++ >= MICROCODE_WORDS) {
                    error_report("milkymist_pfpu: too many instructions "
                            "executed in microcode. No VECTOUT?\n");
                    break;
                }
            }

            /* reset pc for next run */
            s->regs[R_PC] = 0;
        }
    }

    s->regs[R_VERTICES] = x * y;

    trace_milkymist_pfpu_pulse_irq();
    qemu_irq_pulse(s->irq);
}

static inline int get_microcode_address(MilkymistPFPUState *s, uint32_t addr)
{
    return (512 * s->regs[R_CODEPAGE]) + addr - MICROCODE_BEGIN;
}

static uint32_t pfpu_read(void *opaque, target_phys_addr_t addr)
{
    MilkymistPFPUState *s = opaque;
    uint32_t r = 0;

    addr >>= 2;
    switch (addr) {
    case R_CTL:
    case R_MESHBASE:
    case R_HMESHLAST:
    case R_VMESHLAST:
    case R_CODEPAGE:
    case R_VERTICES:
    case R_COLLISIONS:
    case R_STRAYWRITES:
    case R_LASTDMA:
    case R_PC:
    case R_DREGBASE:
    case R_CODEBASE:
        r = s->regs[addr];
        break;
    case GPR_BEGIN ... GPR_END:
        r = s->gp_regs[addr - GPR_BEGIN];
        break;
    case MICROCODE_BEGIN ...  MICROCODE_END:
        r = s->microcode[get_microcode_address(s, addr)];
        break;

    default:
        error_report("milkymist_pfpu: read access to unknown register 0x"
                TARGET_FMT_plx, addr << 2);
        break;
    }

    trace_milkymist_pfpu_memory_read(addr << 2, r);

    return r;
}

static void
pfpu_write(void *opaque, target_phys_addr_t addr, uint32_t value)
{
    MilkymistPFPUState *s = opaque;

    trace_milkymist_pfpu_memory_write(addr, value);

    addr >>= 2;
    switch (addr) {
    case R_CTL:
        if (value & CTL_START_BUSY) {
            pfpu_start(s);
        }
        break;
    case R_MESHBASE:
    case R_HMESHLAST:
    case R_VMESHLAST:
    case R_CODEPAGE:
    case R_VERTICES:
    case R_COLLISIONS:
    case R_STRAYWRITES:
    case R_LASTDMA:
    case R_PC:
    case R_DREGBASE:
    case R_CODEBASE:
        s->regs[addr] = value;
        break;
    case GPR_BEGIN ...  GPR_END:
        s->gp_regs[addr - GPR_BEGIN] = value;
        break;
    case MICROCODE_BEGIN ...  MICROCODE_END:
        s->microcode[get_microcode_address(s, addr)] = value;
        break;

    default:
        error_report("milkymist_pfpu: write access to unknown register 0x"
                TARGET_FMT_plx, addr << 2);
        break;
    }
}

static CPUReadMemoryFunc * const pfpu_read_fn[] = {
    NULL,
    NULL,
    &pfpu_read,
};

static CPUWriteMemoryFunc * const pfpu_write_fn[] = {
    NULL,
    NULL,
    &pfpu_write,
};

static void milkymist_pfpu_reset(DeviceState *d)
{
    MilkymistPFPUState *s = container_of(d, MilkymistPFPUState, busdev.qdev);
    int i;

    for (i = 0; i < R_MAX; i++) {
        s->regs[i] = 0;
    }
    for (i = 0; i < 128; i++) {
        s->gp_regs[i] = 0;
    }
    for (i = 0; i < MICROCODE_WORDS; i++) {
        s->microcode[i] = 0;
    }
    s->output_queue_pos = 0;
    for (i = 0; i < MAX_LATENCY; i++) {
        s->output_queue[i] = 0;
    }
}

static int milkymist_pfpu_init(SysBusDevice *dev)
{
    MilkymistPFPUState *s = FROM_SYSBUS(typeof(*s), dev);
    int pfpu_regs;

    sysbus_init_irq(dev, &s->irq);

    pfpu_regs = cpu_register_io_memory(pfpu_read_fn, pfpu_write_fn, s,
            DEVICE_NATIVE_ENDIAN);
    sysbus_init_mmio(dev, MICROCODE_END * 4, pfpu_regs);

    return 0;
}

static const VMStateDescription vmstate_milkymist_pfpu = {
    .name = "milkymist-pfpu",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields      = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, MilkymistPFPUState, R_MAX),
        VMSTATE_UINT32_ARRAY(gp_regs, MilkymistPFPUState, 128),
        VMSTATE_UINT32_ARRAY(microcode, MilkymistPFPUState, MICROCODE_WORDS),
        VMSTATE_INT32(output_queue_pos, MilkymistPFPUState),
        VMSTATE_UINT32_ARRAY(output_queue, MilkymistPFPUState, MAX_LATENCY),
        VMSTATE_END_OF_LIST()
    }
};

static SysBusDeviceInfo milkymist_pfpu_info = {
    .init = milkymist_pfpu_init,
    .qdev.name  = "milkymist-pfpu",
    .qdev.size  = sizeof(MilkymistPFPUState),
    .qdev.vmsd  = &vmstate_milkymist_pfpu,
    .qdev.reset = milkymist_pfpu_reset,
};

static void milkymist_pfpu_register(void)
{
    sysbus_register_withprop(&milkymist_pfpu_info);
}

device_init(milkymist_pfpu_register)

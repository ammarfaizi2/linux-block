.. SPDX-License-Identifier: GPL-2.0

RISC-V Hardware Probing Interface
---------------------------------

The RISC-V hardware probing interface is based around a single syscall, which
is defined in <asm/hwprobe.h>::

    struct riscv_hwprobe {
        __u64 key, value;
    };

    long sys_riscv_hwprobe(struct riscv_hwprobe *pairs, size_t pair_count,
                           size_t base_key, size_t cpu_count, cpu_set_t *cpus,
                           unsigned long flags);

The arguments are split into three groups: an array of key-value pairs, a CPU
set, and some flags.  The key-value pairs are supplied with a count and an
base, which is the first key that will be probed for.  The CPU set is defined
by CPU_SET(3), the indicated features will be supported on all CPUs in the set.
There are currently no flags, this value must be zero for future compatibility.

On success the number of filled out pairs is returned, on failure a negative
error code is returned.

The following keys are defined:

* :RISCV_HWPROBE_KEY_MVENDORID:: Contains the value of :mvendorid:, as per the
  ISA specifications.
* :RISCV_HWPROBE_KEY_MARCHID:: Contains the value of :marchid:, as per the ISA
  specifications.
* :RISCV_HWPROBE_KEY_MIMPLID:: Contains the value of :mimplid:, as per the ISA
  specifications.

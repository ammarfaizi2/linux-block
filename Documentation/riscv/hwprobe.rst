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
* :RISCV_HWPROBE_KEY_BASE_BEHAVIOR:: A bitmask containing the base user-visible
  behavior that this kernel supports.  The following base user ABIs are defined:
    * :RISCV_HWPROBE_BASE_BEHAVIOR_IMA:: Support for rv32ima or rv64ima, as
      defined by version 2.2 of the user ISA and version 1.10 of the privileged
      ISA, with the following known exceptions (more exceptions may be added,
      but only if it can be demonstrated that the user ABI is not broken):
        * The :fence.i: instruction cannot be directly executed by userspace
          programs (it may still be executed in userspace via a
          kernel-controlled mechanism such as the vDSO).
* :RISCV_HWPROBE_KEY_IMA_EXT_0:: A bitmask containing the extensions that are
  compatible with the :RISCV_HWPROBE_BASE_BEHAVIOR_IMA: base system behavior.
    * :RISCV_HWPROBE_IMA_FD:: The F and D extensions are supported, as defined
      by commit cd20cee ("FMIN/FMAX now implement minimumNumber/maximumNumber,
      not minNum/maxNum") of the RISC-V ISA manual.
    * :RISCV_HWPROBE_IMA_C:: The C extension is supported, as defined by
      version 2.2 of the RISC-V ISA manual.

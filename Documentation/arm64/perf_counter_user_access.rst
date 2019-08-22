=============================================
Access to PMU hardware counter from userspace
=============================================

Overview
--------
The perf userspace tool relies on the PMU to monitor events. It offers an
abstraction layer over the hardware counters since the underlying
implementation is cpu-dependent.
Arm64 allows userspace tools to have access to the registers storing the
hardware counters' values directly.

This targets specifically self-monitoring tasks in order to reduce the overhead
by directly accessing the registers without having to go through the kernel.

How-to
------
The focus is set on the armv8 pmuv3 which makes sure that the access to the pmu
registers is enabled and that the userspace has access to the relevant
information in order to use them.

In order to have access to the hardware counter it is necessary to open the event
using the perf tool interface: the sys_perf_event_open syscall returns a fd which
can subsequently be used with the mmap syscall in order to retrieve a page of
memory containing information about the event.
The PMU driver uses this page to expose to the user the hardware counter's
index and other necessary data. Using this index enables the user to access the
PMU registers using the `mrs` instruction.

The userspace access is supported in libperf using the perf_evsel__mmap()
and perf_evsel__read() functions. See `tools/lib/perf/tests/test-evsel.c`_ for
an example.

About heterogeneous systems
---------------------------
On heterogeneous systems such as big.LITTLE, userspace PMU counter access can
only be enabled when the tasks are pinned to a homogeneous subset of cores and
the corresponding PMU instance is opened by specifying the 'type' attribute.
The use of generic event types is not supported in this case.

Have a look at `tools/perf/arch/arm64/tests/user-events.c`_ for an example. It
can be run using the perf tool to check that the access to the registers works
correctly from userspace:

.. code-block:: sh

  perf test -v user

About chained events
--------------------
Chained events are not supported in userspace. If a 64-bit counter is requested,
userspace access will only be enabled if the underlying counter is 64-bit.

.. Links
.. _tools/perf/arch/arm64/tests/user-events.c:
   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/perf/arch/arm64/tests/user-events.c

.. SPDX-License-Identifier: GPL-2.0

.. _block:

======
zblock
======

Zblock stores integer number of compressed objects per block. These
blocks consist of several consecutive physical pages (from 1 to 8) and
are arranged in lists. The range from 0 to PAGE_SIZE is divided into the
number of intervals corresponding to the number of lists and each list
only operates objects of size from its interval. Thus the block lists are
isolated from each other, which makes it possible to simultaneously
perform actions with several objects from different lists.

Blocks make it possible to densely arrange objects of various sizes
resulting in low internal fragmentation. Also this allocator tries to fill
incomplete blocks instead of adding new ones thus in many cases providing
a compression ratio substantially higher than z3fold and zbud. Zblock does
not require MMU and also is superior to zsmalloc with regard to the worst
execution times, thus allowing for better response time and real-time
characteristics of the whole system.

Like z3fold and zsmalloc zblock_alloc() does not return a dereferenceable
pointer. Instead, it returns an unsigned long handle which encodes actual
location of the allocated object.

Unlike zbud and z3fold zblock works well with objects of various sizes - both
highly compressed and poorly compressed including cases where both types
are present.

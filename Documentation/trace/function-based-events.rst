=====================
Function based events
=====================

.. Copyright 2018 VMware Inc.
..   Author:   Steven Rostedt <srostedt@goodmis.org>
..  License:   The GNU Free Documentation License, Version 1.2
..               (dual licensed under the GPL v2)


Introduction
============

Static events are extremely useful for analyzing the happenings of
inside the Linux kernel. But there are times where events are not
available, either due to not being in control of the kernel, or simply
because a maintainer refuses to have them in their subsystem.

The function tracer is a way trace within a subsystem without trace events.
But it only provides information of when a function was hit and who
called it. Combining trace events with the function tracer allows
for dynamically creating trace events where they do not exist at
function entry. They provide more information than the function
tracer can provide, as they can read the parameters of a function
or simply read an address. This makes it possible to create a
trace point at any function that the function tracer can trace, and
read the parameters of the function.


Usage
=====

Simply writing an ASCII string into a file called "function_events"
in the tracefs file system will create the function based events.
Note, this file is only writable by root.

 # mount -t tracefs nodev /sys/kernel/tracing
 # cd /sys/kernel/tracing
 # echo 'do_IRQ()' > function_events

The above will create a trace event on the do_IRQ function call.
As no parameters were specified, it will not trace anything other
than the function and the parent. This is the minimum function
based event.

 # ls events/functions/do_IRQ
enable  filter  format  hist  id  trigger

Even though the above function based event does not record much more
than the function tracer does, it does become a full fledge event.
This can be used by the histogram infrastructure, and triggers.

 # cat events/functions/do_IRQ/format
name: do_IRQ
ID: 1304
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __parent_ip;	offset:8;	size:8;	signed:0;
	field:unsigned long __ip;	offset:16;	size:8;	signed:0;

print fmt: "%pS->%pS()", REC->__ip, REC->__parent_ip

The above shows that the format is very close to the function trace
except that it displays the parent function followed by the called
function.


Number of arguments
===================

The number of arguments that can be specified is dependent on the
architecture. An architecture may not allow any arguments, or it
may limit to just three or six. If more arguments are used than
supported, it will fail with -EINVAL.

Parameters
==========

Adding parameters creates fields within the events. The format is
as follows:

 # echo EVENT > function_events

 EVENT := <function> '(' ARGS ')'

 Where <function> is any function that the function tracer can trace.

 ARGS := ARG | ARG ',' ARGS | ''

 ARG := TYPE FIELD | TYPE <name> '=' ADDR | TYPE ADDR | ARG '|' ARG | 'NULL'

 TYPE := ATOM | ATOM '[' <number> ']' | 'unsigned' TYPE

 ATOM := 'u8' | 'u16' | 'u32' | 'u64' |
         's8' | 's16' | 's32' | 's64' |
         'x8' | 'x16' | 'x32' | 'x64' |
         'char' | 'short' | 'int' | 'long' | 'size_t' |
	 'symbol' | 'string'

 FIELD := <name> | <name> INDEX | <name> OFFSET | <name> OFFSET INDEX |
	 FIELD INDIRECT

 INDEX := '[' <number> ']'

 OFFSET := '+' <number>

 INDIRECT := INDEX | OFFSET | INDIRECT INDIRECT | ''

 ADDR := A hexidecimal address starting with '0x'

 Where <name> is a unique string starting with an alphabetic character
 and consists only of letters and numbers and underscores.

 Where <number> is a number that can be read by kstrtol() (hex, decimal, etc).


Simple arguments
================

Looking at kernel code, we can see something like:

 v4.15: net/ipv4/ip_input.c:

int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)

If we are only interested in the first argument (skb):

 # echo 'ip_rcv(x64 skb, x86 dev)' > function_events

 # echo 1 > events/functions/ip_rcv/enable
 # cat trace
     <idle>-0     [003] ..s3  5543.133460: __netif_receive_skb_core->ip_rcv(skb=ffff88007f960700, net=ffff880114250000)
     <idle>-0     [003] ..s3  5543.133475: __netif_receive_skb_core->ip_rcv(skb=ffff88007f960700, net=ffff880114250000)
     <idle>-0     [003] ..s3  5543.312592: __netif_receive_skb_core->ip_rcv(skb=ffff88007f960700, net=ffff880114250000)
     <idle>-0     [003] ..s3  5543.313150: __netif_receive_skb_core->ip_rcv(skb=ffff88007f960700, net=ffff880114250000)

We use "x64" in order to make sure that the data is displayed in hex.
This is on a x86_64 machine, and we know the pointer sizes are 8 bytes.


Indexing
========

The pointers of the skb and the dev isn't that interesting. But if we want the
length "len" field of skb, we could index it with an index operator '[' and ']'.

Using gdb, we can find the offset of 'len' from the sk_buff type:

 $ gdb vmlinux
 (gdb) printf "%d\n", &((struct sk_buff *)0)->len
128

As 128 / 4 (length of int) is 32, we can see the length of the skb with:

 # echo 'ip_rcv(int skb[32], x64 dev)' > function_events

 # echo 1 > events/functions/ip_rcv/enable
 # cat trace
    <idle>-0     [003] ..s3   280.167137: __netif_receive_skb_core->ip_rcv(skb=52, dev=ffff8801092f9400)
    <idle>-0     [003] ..s3   280.167152: __netif_receive_skb_core->ip_rcv(skb=52, dev=ffff8801092f9400)
    <idle>-0     [003] ..s3   280.806629: __netif_receive_skb_core->ip_rcv(skb=88, dev=ffff8801092f9400)
    <idle>-0     [003] ..s3   280.807023: __netif_receive_skb_core->ip_rcv(skb=52, dev=ffff8801092f9400)

Now we see the length of the sk_buff per event.


Multiple fields per argument
============================


If we still want to see the skb pointer value along with the length of the
skb, then using the '|' option allows us to add more than one option to
an argument:

 # echo 'ip_rcv(x64 skb | int skb[32], x64 dev)' > function_events

 # echo 1 > events/functions/ip_rcv/enable
 # cat trace
    <idle>-0     [003] ..s3   904.075838: __netif_receive_skb_core->ip_rcv(skb=ffff88011396e800, skb=52, dev=ffff880115204000)
    <idle>-0     [003] ..s3   904.075848: __netif_receive_skb_core->ip_rcv(skb=ffff88011396e800, skb=52, dev=ffff880115204000)
    <idle>-0     [003] ..s3   904.725486: __netif_receive_skb_core->ip_rcv(skb=ffff88011396e800, skb=194, dev=ffff880115204000)
    <idle>-0     [003] ..s3   905.152537: __netif_receive_skb_core->ip_rcv(skb=ffff88011396f200, skb=88, dev=ffff880115204000)


Unsigned usage
==============

One can also use "unsigned" to make some types unsigned. It works against
"long", "int", "short" and "char". It doesn't error against other types but
may not make any sense.

 # echo 'ip_rcv(int skb[32])' > function_events
 # cat events/functions/ip_rcv/format
name: ip_rcv
ID: 1397
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __parent_ip;	offset:8;	size:8;	signed:0;
	field:unsigned long __ip;	offset:16;	size:8;	signed:0;
	field:int skb;	offset:24;	size:4;	signed:1;

print fmt: "%pS->%pS(skb=%d)", REC->__ip, REC->__parent_ip, REC->skb


Notice that REC->skb is printed with "%d". By adding "unsigned"

 # echo 'ip_rcv(unsigned int skb[32])' > function_events
 # cat events/functions/ip_rcv/format
name: ip_rcv
ID: 1398
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __parent_ip;	offset:8;	size:8;	signed:0;
	field:unsigned long __ip;	offset:16;	size:8;	signed:0;
	field:unsigned int skb;	offset:24;	size:4;	signed:0;

print fmt: "%pS->%pS(skb=%u)", REC->__ip, REC->__parent_ip, REC->skb

It is now printed with a "%u".


Offsets
=======

After the name of the variable, brackets '[' number ']' will index the value of
the argument by the number given times the size of the field.

 int field[5] will dereference the value of the argument 20 bytes away (4 * 5)
  as sizeof(int) is 4.

If there's a case where the type is of 8 bytes in size but is not 8 bytes
alligned in the structure, an offset may be required.

  For example: x64 param+4[2]

The above will take the parameter value, add it by 4, then index it by two
8 byte words. It's the same in C as: (u64 *)((void *)param + 4)[2]

 Note: "int skb[32]" is the same as "int skb+4[31]".


Symbols (function names)
========================

To display kallsyms "%pS" type of output, use the special type "symbol".

Again, using gdb to find the offset of the "func" field of struct work_struct

(gdb) printf "%d\n", &((struct work_struct *)0)->func
24

 Both "symbol func[3]" and "symbol func+24[0]" will work.

 # echo '__queue_work(int cpu, x64 wq, symbol func[3])' > function_events

 # echo 1 > events/functions/__queue_work/enable
 # cat trace
       bash-1641  [007] d..2  6241.171332: queue_work_on->__queue_work(cpu=128, wq=ffff88011a010e00, func=flush_to_ldisc+0x0/0xa0)
       bash-1641  [007] d..2  6241.171460: queue_work_on->__queue_work(cpu=128, wq=ffff88011a010e00, func=flush_to_ldisc+0x0/0xa0)
     <idle>-0     [000] dNs3  6241.172004: delayed_work_timer_fn->__queue_work(cpu=128, wq=ffff88011a010800, func=vmstat_shepherd+0x0/0xb0)
 worker/0:2-1689  [000] d..2  6241.172026: __queue_delayed_work->__queue_work(cpu=7, wq=ffff88011a11da00, func=vmstat_update+0x0/0x70)
     <idle>-0     [005] d.s3  6241.347996: queue_work_on->__queue_work(cpu=128, wq=ffff88011a011200, func=fb_flashcursor+0x0/0x110 [fb])


Direct memory access
====================

Function arguments are not the only thing that can be recorded from a function
based event. Memory addresses can also be examined. If there's a global variable
that you want to monitor via an interrupt, you can put in the address directly.

  # grep total_forks /proc/kallsyms
ffffffff82354c18 B total_forks

  # echo 'do_IRQ(int total_forks=0xffffffff82354c18)' > function_events

  # echo 1 events/functions/do_IRQ/enable
  # cat trace
    <idle>-0     [003] d..3   337.076709: ret_from_intr->do_IRQ(total_forks=1419)
    <idle>-0     [003] d..3   337.077046: ret_from_intr->do_IRQ(total_forks=1419)
    <idle>-0     [003] d..3   337.077076: ret_from_intr->do_IRQ(total_forks=1420)

Note, address notations do not affect the argument count. For instance, with

__visible unsigned int __irq_entry do_IRQ(struct pt_regs *regs)

  # echo 'do_IRQ(int total_forks=0xffffffff82354c18, symbol regs[16])' > function_events

Is the same as

  # echo 'do_IRQ(int total_forks=0xffffffff82354c18 | symbol regs[16])' > function_events

  # cat trace
    <idle>-0     [003] d..3   653.839546: ret_from_intr->do_IRQ(total_forks=1504, regs=cpuidle_enter_state+0xb1/0x330)
    <idle>-0     [003] d..3   653.906011: ret_from_intr->do_IRQ(total_forks=1504, regs=cpuidle_enter_state+0xb1/0x330)
    <idle>-0     [003] d..3   655.823498: ret_from_intr->do_IRQ(total_forks=1504, regs=tick_nohz_idle_enter+0x4c/0x50)
    <idle>-0     [003] d..3   655.954096: ret_from_intr->do_IRQ(total_forks=1504, regs=cpuidle_enter_state+0xb1/0x330)


Array types
===========

If there's a case where you want to see an array of a type, then you can
declare a type as an array by adding '[' number ']' after the type.

To get the net_device perm_addr, from the dev parameter.

 (gdb) printf "%d\n", &((struct net_device *)0)->perm_addr
558

 # echo 'ip_rcv(x64 skb, x8[6] perm_addr+558)' > function_events

 # echo 1 > events/functions/ip_rcv/enable
 # cat trace
    <idle>-0     [003] ..s3   219.813582: __netif_receive_skb_core->ip_rcv(skb=ffff880118195e00, perm_addr=b4,b5,2f,ce,18,65)
    <idle>-0     [003] ..s3   219.813595: __netif_receive_skb_core->ip_rcv(skb=ffff880118195e00, perm_addr=b4,b5,2f,ce,18,65)
    <idle>-0     [003] ..s3   220.115053: __netif_receive_skb_core->ip_rcv(skb=ffff880118195c00, perm_addr=b4,b5,2f,ce,18,65)
    <idle>-0     [003] ..s3   220.115293: __netif_receive_skb_core->ip_rcv(skb=ffff880118195c00, perm_addr=b4,b5,2f,ce,18,65)


Static strings
==============

An array of type 'char' or 'unsigned char' will be processed as a string using
the format "%s". If a nul is found, the output will stop. Use another type
(x8, u8, s8) if this is not desired.

  # echo 'link_path_walk(char[64] name)' > function_events

  # echo 1 > events/functions/link_path_walk/enable
  # cat trace
      bash-1470  [003] ...2   980.678664: path_openat->link_path_walk(name=/usr/bin/cat)
      bash-1470  [003] ...2   980.678715: path_openat->link_path_walk(name=/lib64/ld-linux-x86-64.so.2)
      bash-1470  [003] ...2   980.678721: path_openat->link_path_walk(name=ld-2.24.so)
      bash-1470  [003] ...2   980.678978: path_lookupat->link_path_walk(name=/etc/ld.so.preload)


Dynamic strings
===============

Static strings are fine, but they can waste a lot of memory in the ring buffer.
The above allocated 64 bytes for a character array, but most of the output was
less than 20 characters. Not wanting to truncate strings or waste space on
the ring buffer, the dynamic string can help.

Use the "string" type for strings that have a large range in size. The max
size that will be recorded is 512 bytes. If a string is larger than that, then
it will be truncated.

 # echo 'link_path_walk(string name)' > function_events

Gives the same result as above, but does not waste buffer space.


NULL arguments
==============

If you are only interested in the second, or later parameter of a function,
you do not have to record the previous parameters. Just set them as NULL and
they will not be recorded.

If we only wanted the perm_addr of the net_device of ip_rcv() and not the
sk_buff, we put a NULL into the first parameter when created the function
based event.

  # echo 'ip_rcv(NULL, x8[6] perm_addr+558)' > function_events

  # echo 1 > events/functions/ip_rcv/enable
  # cat trace
    <idle>-0     [003] ..s3   165.617114: __netif_receive_skb_core->ip_rcv(perm_addr=b4,b5,2f,ce,18,65)
    <idle>-0     [003] ..s3   165.617133: __netif_receive_skb_core->ip_rcv(perm_addr=b4,b5,2f,ce,18,65)
    <idle>-0     [003] ..s3   166.412277: __netif_receive_skb_core->ip_rcv(perm_addr=b4,b5,2f,ce,18,65)
    <idle>-0     [003] ..s3   166.412797: __netif_receive_skb_core->ip_rcv(perm_addr=b4,b5,2f,ce,18,65)


NULL can appear in any argument, to have them ignored. Note, skipping arguments
does not give you access to later arguments if they are not supported by the
architecture. The architecture only supplies the first set of arguments.


The chain of indirects
======================

When a parameter is a structure, and that structure points to another structure,
the data of that structure can still be found.

ssize_t __vfs_read(struct file *file, char __user *buf, size_t count,
		   loff_t *pos)

has the following code.

	if (file->f_op->read)
		return file->f_op->read(file, buf, count, pos);

To trace all the functions that are called by f_op->read(), that information
can be obtained from the file pointer.

Using gdb again:

   (gdb) printf "%d\n", &((struct file *)0)->f_op
40
   (gdb) printf "%d\n", &((struct file_operations *)0)->read
16

    # echo '__vfs_read(symbol read+40[0]+16)' > function_events

  # echo 1 > events/functions/__vfs_read/enable
  # cat trace
         sshd-1343  [005] ...2   199.734752: vfs_read->__vfs_read(read=tty_read+0x0/0xf0)
         bash-1344  [003] ...2   199.734822: vfs_read->__vfs_read(read=tty_read+0x0/0xf0)
         sshd-1343  [005] ...2   199.734835: vfs_read->__vfs_read(read=tty_read+0x0/0xf0)
 avahi-daemon-910   [003] ...2   200.136740: vfs_read->__vfs_read(read=          (null))
 avahi-daemon-910   [003] ...2   200.136750: vfs_read->__vfs_read(read=          (null))


Or to go a bit more extreme: To get the contents of a system type name
from a file: struct file->f_inode->s_sb->s_type->name

   (gdb) printf "%dn", &((struct file *)0)->f_inode
32
   (gdb) printf "%d\n", &((struct inode *)0)->i_sb
40
   (gdb) printf "%d\n", &((struct super_block *)0)->s_type
40

Since a string does not have a common size, use of offsets must be used,
and only use a zero indirect ([0]).

   # echo '__vfs_read(string name+32[0]+40[0]+40[0][0])' > function_events

To break the above down. The first argument passed to __vfs_read() is
a pointer to a "struct file".

  '__vfs_read(x64 file)' Would return the address of the file.
  '__vfs_read(x64 inode+32[0])' returns the address of the inode indexed in file
  '__vfs_read(x64 sb+32[0]+40[0])' returns the address of the super block indexed
			from the inode.
  '__vfs_read(x64 stype+32[0]+40[0]+40[0])' returns the address of the
			file system type, indexed from the super block.
  '__vfs_read(x64 name+32[0]+40[0]+40[0][0]' returns the address of name, indexed
			from the file system type.

The 'string' type requires the address of the string, where the above produces:

            sshd-806   [000] ...2 939615.584601: vfs_read->__vfs_read(name=devtmpfs)
            sshd-806   [000] ...2 939615.585328: vfs_read->__vfs_read(name=devtmpfs)
            bash-807   [000] ...2 939615.585832: vfs_read->__vfs_read(name=devpts)
            sshd-806   [000] ...2 939617.206237: vfs_read->__vfs_read(name=sockfs)
            sshd-806   [000] ...2 939617.207103: vfs_read->__vfs_read(name=devtmpfs)

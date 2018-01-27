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

 ARG := TYPE FIELD | ARG '|' ARG

 TYPE := ATOM | 'unsigned' ATOM

 ATOM := 'u8' | 'u16' | 'u32' | 'u64' |
         's8' | 's16' | 's32' | 's64' |
         'x8' | 'x16' | 'x32' | 'x64' |
         'char' | 'short' | 'int' | 'long' | 'size_t'

 FIELD := <name> | <name> INDEX

 INDEX := '[' <number> ']'

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

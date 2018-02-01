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

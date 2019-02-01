# List of programs to build
hostprogs-$(CONFIG_SAMPLE_WATCH_QUEUE) := watch_test

# Tell kbuild to always build the programs
always := $(hostprogs-y)

HOSTCFLAGS_watch_test.o += -I$(objtree)/usr/include

HOSTLOADLIBES_watch_test += -lkeyutils

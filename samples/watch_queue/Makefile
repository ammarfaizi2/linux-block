# List of programs to build
hostprogs-y := watch_test watch_epoll

# Tell kbuild to always build the programs
always := $(hostprogs-y)

HOSTCFLAGS_watch_test.o += -I$(objtree)/usr/include
HOSTLDLIBS_watch_test += -lkeyutils

HOSTCFLAGS_watch_epoll.o += -I$(objtree)/usr/include
HOSTLDLIBS_watch_epoll += -lpthread -lnuma

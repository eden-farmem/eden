DPDK_PATH = dpdk
PKGCONF ?= pkg-config
INC     = -I./inc
CFLAGS  = -g -Wall -std=gnu11 -D_GNU_SOURCE $(INC) -mssse3
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS = -T base/base.ld -no-pie
LD	= gcc
CC	= gcc
AR	= ar
SPARSE	= sparse
# uncomment to autodetect MLX5
MLX5=$(shell lspci | grep 'ConnectX-5' || echo "")
# MLX4=$(shell lspci | grep 'ConnectX-3' || echo "")

CHECKFLAGS = -D__CHECKER__ -Waddress-space

ifneq ($(DEBUG),)
CFLAGS += -DDEBUG -DCCAN_LIST_DEBUG -rdynamic -O0 -ggdb
LDFLAGS += -rdynamic
else
ifneq ($(GDB),)
CFLAGS += -g -ggdb -O0
else
CFLAGS += -O3
endif
endif

ifneq ($(SAFEMODE),)
CFLAGS += -DSAFEMODE
endif

ifneq ($(NUMA_NODE),)
CFLAGS += -DNUMA_NODE=$(NUMA_NODE)
endif

ifneq ($(EXCLUDE_CORES),)
CFLAGS += -DEXCLUDE_CORES=$(EXCLUDE_CORES)
endif

ifneq ($(REMOTE_MEMORY),)
CFLAGS += -DREMOTE_MEMORY
endif

ifneq ($(REMOTE_MEMORY_HINTS),)
CFLAGS += -DREMOTE_MEMORY
CFLAGS += -DREMOTE_MEMORY_HINTS
endif

ifneq ($(STATS_CORE),)
CFLAGS += -DSTATS_CORE=$(STATS_CORE)
endif

ifneq ($(PROVIDED_CFLAGS),)
CFLAGS += $(PROVIDED_CFLAGS)
endif

ifneq ($(TCP_RX_STATS),)
CFLAGS += -DTCP_RX_STATS
endif

ifneq ($(MLX5),)
CFLAGS += -DMLX5
else
ifneq ($(MLX4),)
CFLAGS += -DMLX4
endif
endif

# handy for debugging
print-%  : ; @echo $* = $($*)

# libbase.a - the base library
base_src = $(wildcard base/*.c)
base_obj = $(base_src:.c=.o)

#libnet.a - a packet/networking utility library
net_src = $(wildcard net/*.c) $(wildcard net/ixgbe/*.c)
net_obj = $(net_src:.c=.o)

# iokernel - a soft-NIC service
iokernel_src = $(wildcard iokernel/*.c)
iokernel_obj = $(iokernel_src:.c=.o)
iokernel_noht_obj = $(iokernel_src:.c=-noht.o)

# runtime - a user-level threading and networking library
runtime_src = $(wildcard runtime/*.c) $(wildcard runtime/net/*.c) $(wildcard runtime/rmem/*.c)
runtime_asm = $(wildcard runtime/*.S)
runtime_obj = $(runtime_src:.c=.o) $(runtime_asm:.S=.o)

# controller - remote memory controller
rcntrl_src = rmem/rcntrl.c rmem/rdma.c
rcntrl_obj = $(rcntrl_src:.c=.o)

# memserver - remote memory server
memserver_src = rmem/memserver.c rmem/rdma.c
memserver_obj = $(memserver_src:.c=.o)

# test cases
test_src = $(wildcard tests/*.c)
test_obj = $(test_src:.c=.o)
test_targets = $(basename $(test_src))

# dpdk libs
# DPDK_LIBS= -L$(DPDK_PATH)/build/lib
# DPDK_LIBS += -Wl,-whole-archive -lrte_pmd_e1000 -Wl,-no-whole-archive
# DPDK_LIBS += -Wl,-whole-archive -lrte_pmd_ixgbe -Wl,-no-whole-archive
# DPDK_LIBS += -Wl,-whole-archive -lrte_mempool_ring -Wl,-no-whole-archive
# DPDK_LIBS += -ldpdk
# DPDK_LIBS += -lrte_eal
# DPDK_LIBS += -lrte_ethdev
# DPDK_LIBS += -lrte_hash
# DPDK_LIBS += -lrte_mbuf
# DPDK_LIBS += -lrte_mempool
# DPDK_LIBS += -lrte_mempool
# DPDK_LIBS += -lrte_mempool_stack
# DPDK_LIBS += -lrte_ring
# # additional libs for running with Mellanox NICs
# ifneq ($(MLX5),)
# DPDK_LIBS +=  -lrte_pmd_mlx5 -libverbs -lmlx5 -lmnl
# else
# ifneq ($(MLX4),)
# DPDK_LIBS += -lrte_pmd_mlx4 -libverbs -lmlx4
# endif
# endif
DPDK_LIBS = $(shell $(PKGCONF) --static --libs libdpdk)

# must be first
all: runtime iok $(test_targets)

runtime: libs rcntrl memserver

libs: libbase.a libnet.a libruntime.a 

iok: iokerneld iokerneld-noht

libbase.a: $(base_obj)
	$(AR) rcs $@ $^

libnet.a: $(net_obj)
	$(AR) rcs $@ $^

libruntime.a: $(runtime_obj)
	$(AR) rcs $@ $^

iokerneld: $(iokernel_obj) libbase.a libnet.a base/base.ld
	$(LD) $(LDFLAGS) -o $@ $(iokernel_obj) libbase.a libnet.a $(DPDK_LIBS) \
	-lpthread -lnuma -ldl

iokerneld-noht: $(iokernel_noht_obj) libbase.a libnet.a base/base.ld
	$(LD) $(LDFLAGS) -o $@ $(iokernel_noht_obj) libbase.a libnet.a $(DPDK_LIBS) \
	 -lpthread -lnuma -ldl

rcntrl: $(rcntrl_obj) libbase.a 
	$(LD) $(LDFLAGS) -o $@ $(rcntrl_obj) libbase.a -lpthread -lrdmacm -libverbs

memserver: $(memserver_obj) libbase.a 
	$(LD) $(LDFLAGS) -o $@ $(memserver_obj) libbase.a -lpthread -lrdmacm -libverbs

$(test_targets): $(test_obj) libbase.a libruntime.a libnet.a base/base.ld
	$(LD) $(LDFLAGS) -o $@ $@.o libruntime.a libnet.a libbase.a -lpthread -lrdmacm -libverbs

# general build rules for all targets
src = $(base_src) $(net_src) $(runtime_src) $(iokernel_src) $(test_src) $(rcntrl_src) $(memserver_src)
asm = $(runtime_asm)
obj = $(src:.c=.o) $(asm:.S=.o) $(iokernel_src:.c=-noht.o) $(rcntrl_src:.c=.o) $(memserver_src:.c=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)   # include all dep files in the makefile
endif

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%-noht.d %.d: %.c
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@

%-noht.o: %.c
	$(CC) $(CFLAGS) -Wno-unused-variable -DCORES_NOHT -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
%.d: %.S
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

# prints sparse checker tool output
sparse: $(src)
	$(foreach f,$^,$(SPARSE) $(filter-out -std=gnu11, $(CFLAGS)) $(CHECKFLAGS) $(f);)

.PHONY: clean
clean:
	rm -f $(obj) $(dep) libbase.a libnet.a libruntime.a \
	iokerneld iokerneld-noht rcntrl memserver $(test_targets)

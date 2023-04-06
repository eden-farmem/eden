INC     = -I../inc
CFLAGS  = -g -Wall -std=gnu11 -D_GNU_SOURCE $(INC) -mssse3
LDFLAGS = -T../base/base.ld -no-pie
LD	= gcc
CC	= gcc
AR	= ar

# Path and dir of this makefile
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(dir $(MKFILE_PATH))

ifneq ($(DEBUG),)
CFLAGS += -DDEBUG -DCCAN_LIST_DEBUG -rdynamic -O0 -ggdb
LDFLAGS += -rdynamic
else
CFLAGS += -DNDEBUG -O3
endif

ifneq ($(NUMA_NODE),)
CFLAGS += -DNUMA_NODE=$(NUMA_NODE)
endif

# handy for debugging
print-%  : ; @echo $* = $($*)

# libshim.a - the shenango shim library
shim_src = $(wildcard *.c)
shim_obj = $(shim_src:.c=.o)

# jemalloc dependency
JEMALLOC_PATH = ${MKFILE_DIR}/../jemalloc
JEMALLOC_INC = $(shell cat $(JEMALLOC_PATH)/je_includes)
JEMALLOC_LIBS = $(shell cat $(JEMALLOC_PATH)/je_libs)
JEMALLOC_STATIC_LIBS = $(shell cat $(JEMALLOC_PATH)/je_static_libs)
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(JEMALLOC_STATIC_LIBS),)
$(error JEMALLOC libs not found. Please run "./setup.sh -je -f" in shenango dir)
endif
endif
CFLAGS += $(JEMALLOC_INC)

# must be first
all: libshim.a

# NOTE: technically there is no need to parcel jemalloc as a part of libshim.a
# but it avoids the need to link jemalloc in every app so we do it here
libshim.a: $(shim_obj)
	$(AR) rcs $@ $^ $(JEMALLOC_STATIC_LIBS)

# general build rules for all targets
src = $(shim_src)
obj = $(src:.c=.o)
dep = $(obj:.o=.d)

ifneq ($(MAKECMDGOALS),clean)
-include $(dep)   # include all dep files in the makefile
endif

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.c
	@$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(obj) $(dep) libshim.a

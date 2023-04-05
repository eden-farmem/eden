# include this Makefile in all subprojects
# define ROOT_PATH before including
ifndef ROOT_PATH
$(error ROOT_PATH is not set)
endif

# shared toolchain definitions
INC = -I$(ROOT_PATH)/inc
FLAGS  = -g -Wall -D_GNU_SOURCE $(INC)
LDFLAGS = -T $(ROOT_PATH)/base/base.ld -no-pie
LD      = gcc
CC      = gcc
LDXX	= g++
CXX		= g++
AR      = ar
SPARSE  = sparse
RUNTIME_LIBS =

## libs for shimming
ifneq ($(EDEN_SHIM),)
# include jemalloc
JEMALLOC_PATH = ${ROOT_PATH}/jemalloc
JEMALLOC_INC = $(shell cat $(JEMALLOC_PATH)/je_includes)
JEMALLOC_LIBS = $(shell cat $(JEMALLOC_PATH)/je_libs)
ifneq ($(MAKECMDGOALS),clean)
ifeq ($(JEMALLOC_LIBS),)
$(error JEMALLOC libs not found. Please run ./setup.sh -je -f in rootdir)
endif
endif
LDFLAGS += $(JEMALLOC_LIBS)

# include shim lib
RUNTIME_LIBS += -ljemalloc $(ROOT_PATH)/shim/libshim.a -ldl
# LDFLAGS += -Wl,--wrap=main
endif

# core libraries to include
RUNTIME_DEPS = $(ROOT_PATH)/libruntime.a $(ROOT_PATH)/librmem.a \
	$(ROOT_PATH)/libnet.a $(ROOT_PATH)/libbase.a
RUNTIME_LIBS += $(ROOT_PATH)/libruntime.a $(ROOT_PATH)/librmem.a \
 	$(ROOT_PATH)/libnet.a $(ROOT_PATH)/libbase.a -lpthread -lrdmacm -libverbs

# parse configuration options
ifeq ($(CONFIG_DEBUG),y)
FLAGS += -DDEBUG -DCCAN_LIST_DEBUG -rdynamic -O0 -ggdb -mssse3
LDFLAGS += -rdynamic
else
FLAGS += -DNDEBUG -O3
ifeq ($(CONFIG_OPTIMIZE),y)
FLAGS += -march=native -flto -ffast-math
else
FLAGS += -mssse3
endif
endif

CFLAGS = -std=gnu11 $(FLAGS)
CXXFLAGS = -std=gnu++17 $(FLAGS)

# handy for debugging
print-%  : ; @echo $* = $($*) 
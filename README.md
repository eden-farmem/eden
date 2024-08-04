
This repository hosts `Eden`, a hybrid userspace + kernel runtime for Far
Memory based on Shenango and Userfaultfd.

# Eden
While Eden modifies Shenango's core runtime at many places to support
page-faults in between thread switching, most Eden-specific code is
concentrated in the following places:  
    - [rmem/](./rmem) : most remote memory/page fault handling code  
    - [runtime/rmem.c](./runtime/rmem.c) : remote memory setup & teardown from Shenango runtime  
    - [runtime/pgfault.c](./runtime/pgfault.c) : page fault handling in Shenango runtime (entry point for Eden's hints)  
    - [shim/mem.c](./shim/mem.c): transparent memory interposition layer with jemalloc-based memory allocations  
    - [tools](./tools): Page fault profiling tool and remote memory server  

## How to build and link Eden
1) Clone the repository.
```
git clone https://github.com/XXX/eden
cd eden
```

2) Setup and build DPDK and jemalloc dependecies. You'll need to 
pick a DPDK version using `-dv=` argument (this depends on your 
Kernel version and NIC drivers that are supported).
```
bash setup.sh -dv=20.11
```

3) Build Eden.
```
make clean && make
```

4) Link Eden. To link Eden with your application, you need to link
libraries produced by the Makefile (see [shared.mk](./shared.mk)) and 
include [inc/runtime/pgfault.h](./inc/runtime/pgfault.h)
to use the hint interface in your application.


## Supported Platforms

This code has been tested most thoroughly on Ubuntu 20.04, with kernel
5.15.0. It has been tested with Mellanox ConnectX-5 Pro 100 Gbits/s
NICs. In addition to the [Shenango](https://github.com/shenango/shenango) requirements , the
remote memory component of Eden requires a RDMA NIC and expects
`rdmacm` and `libibverbs` installed. For best performance, Eden also
requires some unpublished userfaultfd changes in the kernel. See
[kernel patches](./kernel/README.md) for more info.

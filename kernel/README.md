Eden is developed/tested on a custom kernel based on 5.15-rc1 
with a few patches to extend the userfaultfd interface.


To install this kernel, you can follow the steps below.
1. Clone kernel 5.15-rc1
    https://kernel.ubuntu.com/~kernel-ppa/mainline/v5.15-rc1/
2. Apply patches from below.
3. Build and boot into it. Helper scripts at `scripts/kernel/*`

### Available Patches


(Recommended)

1. To enable performance optimizations for Eden, the below patches 
   enable vectored I/O for syscalls in the eviction path. These 
   are required to see the performance benefits of Eden.
   ```
    git am uffd-wprotect-vec.patch
    git am madvise-vec/*.patch
   ```

(Optional)

2. For debugging fault locations, we need code locations. This 
    patch includes ip register value in the fault message sent 
    to userspace so we can locate the fault source. 
    ```
    git am uffd-include-ip.patch
    ```
    This is not necessary for proper functioning of Eden. This is 
    only required for the older versions of the tracing tool.

3. For vDSO page status calls that support page-fault checking without Eden:
    ```
    git am vdso/*.patch
    ```
    These are not necessary for proper functioning of Eden.

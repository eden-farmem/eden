// Copyright © 2018-2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

#ifndef __UFFD_H__
#define __UFFD_H__

int userfaultfd(int flags);
int uffd_init(void);
int uffd_register(int fd, unsigned long addr, size_t size, int writeable);
int uffd_unregister(int fd, unsigned long addr, size_t size);
int uffd_copy(int fd, unsigned long dst, unsigned long src, int wpmode, bool retry, 
    int *n_retries, bool wake_on_exist);
int uffd_copy_size(int fd, unsigned long dst, unsigned long src, size_t size, int wpmode);
int uffd_wp(int fd, unsigned long addr, size_t size, int wpmode, bool retry, int *n_retries);
int uffd_wp_add(int fd, unsigned long fault_addr, size_t size, bool retry, int *n_retries);
int uffd_wp_remove(int fd, unsigned long fault_addr, size_t size, bool retry, int *n_retries);
int uffd_zero(int fd, unsigned long addr, size_t size, bool retry, int *n_retries);
int uffd_wake(int fd, unsigned long addr, size_t size);

// void init_evt_fd(void);
// void add_evt_fd(int fd);

#endif  // __UFFD_H__
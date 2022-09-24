// Copyright © 2018-2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

#ifndef __CONFIG_H__
#define __CONFIG_H__


#include "base/mem.h"
#include "base/assert.h"

/*
 * The chunk size for remote memory handling (must be a power of 2 (KB)).
 */
#define CHUNK_SHIFT PGSHIFT_4KB
#define CHUNK_SIZE  PGSIZE_4KB
#define CHUNK_MASK  PGMASK_4KB
BUILD_ASSERT(CHUNK_SIZE >= PGSIZE_4KB);

#endif  // __CONFIG_H__
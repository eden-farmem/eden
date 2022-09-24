/*
 * rmem.c - remote memory init
 */

#include "defs.h"

bool rmem_enabled = true;    /*TODO: set me to false by default*/


/**
 * rmem_init - initializes remote memory
 */
int rmem_init()
{
    return 0;
}

/**
 * rmem_init_thread - initializes per-thread remote memory support
 */
int rmem_init_thread()
{
    struct kthread *k = myk();
    return 0;
}

/**
 * rmem_init_late - remote memory post-init actions
 */
int rmem_init_late()
{
    return 0;
}

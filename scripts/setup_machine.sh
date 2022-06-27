#!/bin/bash

# run with sudo
sysctl -w kernel.shm_rmid_forced=1
sysctl -w kernel.shmmax=18446744073692774399
sysctl -w vm.hugetlb_shm_group=27
sysctl -w vm.max_map_count=16777216
sysctl -w net.core.somaxconn=3072

echo 4096 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

# for n in /sys/devices/system/node/node[1-9]; do
# 	echo 0 > $n/hugepages/hugepages-2048kB/nr_hugepages
# done
# Anil: It seems like we need pages on all nodes?
echo 4096 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

# Disable turbo: This is temporary and only works with intel pstate driver
# https://askubuntu.com/questions/619875/disabling-intel-turbo-boost-in-ubuntu
echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Diasble automatic NUMA load balancing. This feature raises spurious page 
# faults to determine NUMA node access patterns which interfere with 
# the annotations
echo 0 | sudo tee /proc/sys/kernel/numa_balancing

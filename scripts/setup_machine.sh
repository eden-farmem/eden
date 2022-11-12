#!/bin/bash
set -e

# run with sudo
sysctl -w kernel.shm_rmid_forced=1
sysctl -w kernel.shmmax=18446744073692774399
sysctl -w vm.hugetlb_shm_group=27
sysctl -w vm.max_map_count=16777216
sysctl -w net.core.somaxconn=3072

# setup huge pages
echo 4096 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 4096 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

# Disable turbo: This is temporary and only works with intel pstate driver
# https://askubuntu.com/questions/619875/disabling-intel-turbo-boost-in-ubuntu
echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Disable automatic NUMA load balancing. This feature raises spurious page 
# faults to determine NUMA node access patterns which interfere with 
# the annotations
echo 0 | sudo tee /proc/sys/kernel/numa_balancing

# disable freq scaling and set CPU to a static frequency
# Note that tools with daemons such as cpufrequtils may affect this
governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq)
if [ "$governor" != "performance" ] || [ "$freq" != "2200000" ]; then
    echo "setting cpu freq on all cores"
    N=`nproc`
    for ((cpu=0; cpu<$N; cpu++)); do
        cpudir=/sys/devices/system/cpu/cpu$cpu/cpufreq/
        if [ -d $dir ]; then
            echo "performance" | sudo tee ${cpudir}/scaling_governor
            echo 2200000 | sudo tee ${cpudir}/scaling_min_freq
            echo 2200000 | sudo tee ${cpudir}/scaling_max_freq
        fi
    done
fi
# Check with 
# cat /proc/cpuinfo | grep MHz
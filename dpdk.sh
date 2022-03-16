#!/bin/bash

set -e

# Initialize dpdk module
git submodule init
git submodule update --recursive

# # Apply driver patches
# patch -p 1 -d dpdk/ < ixgbe_19_11.patch

# if lspci | grep -q 'ConnectX-5'; then
#    patch -p 1 -d dpdk/ < mlx5_19_11.patch
# elif lspci | grep -q 'ConnectX-3'; then
#     patch -p 1 -d dpdk/ < mlx4_18_11.patch
#     sed -i 's/CONFIG_RTE_LIBRTE_MLX4_PMD=n/CONFIG_RTE_LIBRTE_MLX4_PMD=y/g' dpdk/config/common_base
# fi
patch -p 1 -d dpdk/ < mlx5_20_11.patch

# # Configure/compile dpdk
# make -C dpdk/ config T=x86_64-native-linuxapp-gcc
# make -C dpdk/ -j
pushd dpdk/
meson build
ninja -C build
sudo ninja -C build install
echo "make sure pkg-config --cflags libdpdk is working at this point!"
popd
#!/bin/bash
set -e

#
# Sets up Shenango dependencies
#

SCRIPT_DIR=`dirname "$0"`
DPDK_DIR=dpdk
DPDK_VER=$1
JEMALLOC_DIR=jemalloc

usage="Example: $1 [args]\n
-dv, --dpdkver \t DPDK version (required)\n
-f, --force \t force clean and setup everything\n
-h, --help \t this usage information message\n"

# parse cli
for i in "$@"
do
case $i in
    -dv|--dpdkver)
    DEBUG="DEBUG=1"
    CFLAGS="$CFLAGS -DDEBUG"
    ;;

    -dv=*|--dpdkver=*)
    DPDK_VER="${i#*=}"
    ;;

    -f| --force)
    FORCE=1
    ;;

    -h|--help)
    echo -e $usage
    exit
    ;;

    *)                      # unknown option
    echo "Unknown Option: $i"
    echo -e $usage
    exit
    ;;
esac
done

# Figure out dpdk config
if [ "$DPDK_VER" == "20.11" ]; then
    # Tested on Ubuntu 20.04 Kernel 5.4, 5.9, 5.10-rc1, 5.15-rc1
    DPDK_COMMIT=b1d36cf828
    MLX_OFED=MLNX_OFED_LINUX-5.7-1.0.2.0-ubuntu20.04-x86_64 
    MLX_PATCH=mlx5_20_11.patch
    DPDK_BUILD_TYPE=meson
elif [ "$DPDK_VER" == "19.11" ]; then
    # Tested on Ubuntu 18.04 Kernel 4.15
    DPDK_COMMIT=7001c8fd
    MLX_OFED=MLNX_OFED_LINUX-5.3-1.0.0.1-ubuntu18.04-x86_64
    MLX_PATCH=mlx5_19_11.patch
    DPDK_BUILD_TYPE=meson
elif [ "$DPDK_VER" == "18.11" ]; then
    # Tested on Ubuntu 18.04  Kernel 4.15, 4.11-fastswap
    DPDK_COMMIT=0da7f445df
    MLX_OFED=MLNX_OFED_LINUX-4.3-1.0.1.0-ubuntu18.04-x86_64
    MLX_PATCH=mlx5_18_11.patch
    DPDK_BUILD_TYPE=make
else
    echo "Required argument DPDK version -dv/--dpdkver"\
    "Valid values are: 20.11 19.11 18.11"
    exit 1
fi

pushd ${SCRIPT_DIR}

# clean
if [[ $FORCE ]];
then
    rm -rf ${DPDK_DIR}
    rm -rf ${JEMALLOC_DIR}
fi

# Initialize & setup DPDK
if [ ! -d ${DPDK_DIR} ]; then
    git submodule update --init ${DPDK_DIR}
    if lspci | grep -q 'ConnectX-5'; then
        echo "ConnectX-5 detected, applying mlx5 patch"
        echo "Make sure mlnx ofed is installed; I'm not gonna do this"
        echo "Tried and tested ofed version for this config: ${MLX_OFED}"
        echo "Use this command: sudo ./mlnxofedinstall --dpdk --upstream-libs --add-kernel-support"
    else
        echo "This script does not support non-ConnectX-5 NICs"
        exit 1
    fi
    pushd ${DPDK_DIR}
    git checkout ${DPDK_COMMIT}
    patch -p 1 -d . < ../patches/${MLX_PATCH}
    popd
fi

# (for ConnectX-3 if we need in future)
# patch -p 1 -d dpdk/ < mlx4_18_11.patch
# sed -i 's/CONFIG_RTE_LIBRTE_MLX4_PMD=n/CONFIG_RTE_LIBRTE_MLX4_PMD=y/g' dpdk/config/common_base

# Build dpdk
pushd ${DPDK_DIR}
if [ "$DPDK_BUILD_TYPE" == "make" ]; then
    if [[ $FORCE ]]; then   rm -rf build;   fi
    make config T=x86_64-native-linuxapp-gcc
    make -j $(nproc)
    libs="-L$(pwd)/build/lib"
    libs="$libs -Wl,-whole-archive -lrte_pmd_e1000 -Wl,-no-whole-archive"
    libs="$libs -Wl,-whole-archive -lrte_pmd_ixgbe -Wl,-no-whole-archive"
    libs="$libs -Wl,-whole-archive -lrte_mempool_ring -Wl,-no-whole-archive"
    libs="$libs -ldpdk"
    libs="$libs -lrte_eal"
    libs="$libs -lrte_ethdev"
    libs="$libs -lrte_hash"
    libs="$libs -lrte_mbuf"
    libs="$libs -lrte_mempool"
    libs="$libs -lrte_mempool"
    libs="$libs -lrte_mempool_stack"
    libs="$libs -lrte_ring"
    # additional libs for running with Mellanox NICs
    libs="$libs -lrte_pmd_mlx5 -libverbs -lmlx5 -lmnl"
    # (for ConnectX-3 MLX4 if we need in future)
    # libs="$libs -lrte_pmd_mlx4 -libverbs -lmlx4"
    echo "$libs" > dpdk_libs
    echo "-I$(pwd)/build/include" > dpdk_includes

elif [ "$DPDK_BUILD_TYPE" == "meson" ]; then
    if [[ $FORCE ]]; then   rm -rf build;   fi
    meson build
    ninja -C build
    sudo ninja -C build install
    libs=$(pkg-config  --static --libs libdpdk)
    if [ -z "$libs" ]; then
        echo "ERROR! pkg-config returned empty string for libdpdk"
        exit 1
    fi
    echo "$libs" > dpdk_libs
    echo "$(pkg-config --cflags libdpdk)" > dpdk_includes
    popd

else 
    echo "Unknown DPDK build type: $DPDK_BUILD_TYPE"
    exit 1
fi
popd

# Initialize & setup jemalloc
if [ ! -d ${JEMALLOC_DIR} ]; then
    git submodule update --init ${JEMALLOC_DIR}
fi

# build
pushd ${JEMALLOC_DIR}
if [[ $FORCE ]]; then   rm -rf build;   fi
autoconf
mkdir -p build
pushd build
../configure --with-jemalloc-prefix=rmlib_je_ --config-cache
make -j$(nproc)
popd

# save paths
JE_BUILD_DIR=`pwd`/build
echo "-L${JE_BUILD_DIR}/lib -Wl,-rpath,${JE_LIB_DIR} -ljemalloc" > je_libs
echo "-I${JE_BUILD_DIR}/include" > je_includes
popd
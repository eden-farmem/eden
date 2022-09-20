#!/bin/bash
set -e

#
# Build Shenango, Kona and other related app code
#

usage="\n
-d, --debug \t\t build debug\n
-n, --sync \t\t sync code base from git (for syncing updates on other machines)\n
-s, --shenango \t build shenango core\n
-sd,--sdpdk \t\t include dpdk in the build\n
-spf,--spgfaults \t build shenango with page faults feature. allowed values: SYNC, ASYNC\n
-sy,--synthetic \t build shenango synthetic app\n
-sb,--sbench \t\t build shenango bench app\n
-wk,--with-kona \t build shenango or apps linked with kona\n
-g, --gdb \t\t build with symbols\n
-h, --help \t\t this usage information message\n"


SCRIPT_PATH=`realpath $0`
SCRIPT_DIR=`dirname ${SCRIPT_PATH}`
ROOTDIR="${SCRIPT_DIR}/../"
SHENANGO_DIR="${ROOTDIR}/scheduler"
KONA_DIR="${ROOTDIR}/backends/kona"

# Parse command line arguments
for i in "$@"
do
case $i in
    -d|--debug)
    DEBUG="DEBUG=1"
    ;;

    -o|--onetime)
    ONETIME=1
    ;;

    -n|--sync)
    SYNC=1
    ;;

    -s|--shenango)
    SHENANGO=1
    ;;

    -sd|--dpdk)
    DPDK=1
    ;;
    
    -spf=*|--spgfaults=*)
    PAGE_FAULTS="${i#*=}"
    KOPTS="$KOPTS -DSERVE_APP_FAULTS"
    ;;

    -so=*|--shenango-cflags=*)
    SOPTS="$SOPTS ${i#*=}"
    ;;

    -m|--memcached)
    SHENANGO=1
    MEMCACHED=1
    ;;

    -sy|--synthetic)
    SHENANGO=1
    SYNTHETIC=1
    NO_STATS=1
    ;;

    -wk|--with-kona)
    WITH_KONA=1
    ;;

    -a|--all)
    SHENANGO=1
    SYNTHETIC=1
    ;;

    # -o=*|--opts=*)    # options 
    # OPTS="${i#*=}"
    # ;;

    -g|--gdb)
    GDB=1
    GDBFLAG="GDB=1"
    GDBFLAG2="--enable-gdb"
    ;;

    -h | --help)
    echo -e $usage
    exit
    ;;

    *)                      # unknown option
    echo "Unkown Option: $i"
    echo -e $usage
    exit
    ;;
esac
done

# Initial CPU allocation
# NUMA node0 CPU(s):   0-13,28-41
# NUMA node1 CPU(s):   14-27,42-55
# RNIC NUMA node = 1
NUMA_NODE=1
KONA_POLLER_CORE=53
KONA_EVICTION_CORE=54
KONA_FAULT_HANDLER_CORE=55
KONA_ACCOUNTING_CORE=52
SHENANGO_STATS_CORE=51
SHENANGO_EXCLUDE=${KONA_POLLER_CORE},${KONA_EVICTION_CORE},\
${KONA_FAULT_HANDLER_CORE},${KONA_ACCOUNTING_CORE},${SHENANGO_STATS_CORE}

if [[ $SYNC ]]; then 
    git submodule update --init --recursive
fi

if [[ $KONA ]]; then 
    pushd ${KONA_DIR}/pbmem
    # make je_clean
    make clean
    make je_jemalloc
    OPTS=
    OPTS="$OPTS POLLER_CORE=$KONA_POLLER_CORE"
    OPTS="$OPTS FAULT_HANDLER_CORE=$KONA_FAULT_HANDLER_CORE"
    OPTS="$OPTS EVICTION_CORE=$KONA_EVICTION_CORE"
    OPTS="$OPTS ACCOUNTING_CORE=${KONA_ACCOUNTING_CORE}"
    make all -j $OPTS $KCFG PROVIDED_CFLAGS="""$KOPTS""" ${DEBUG} ${GDBFLAG}
    sudo sysctl -w vm.unprivileged_userfaultfd=1   
    echo 0 | sudo tee /proc/sys/kernel/numa_balancing   # to avoid numa hint faults 
    popd
fi

if [[ $SHENANGO ]]; then 
    pushd ${SHENANGO_DIR} 
    make clean    
    if [[ $DPDK ]]; then    ./dpdk.sh;  fi
    if [[ $WITH_KONA ]]; then KONA_OPT="WITH_KONA=1";    fi
    if [[ $PAGE_FAULTS ]]; then PGFAULT_OPT="PAGE_FAULTS=$PAGE_FAULTS"; fi
    if ! [[ $NO_STATS ]]; then  STATS_CORE_OPT="STATS_CORE=${SHENANGO_STATS_CORE}"; fi

    make all-but-tests -j ${DEBUG} ${KONA_OPT} ${PGFAULT_OPT}       \
        NUMA_NODE=${NUMA_NODE} EXCLUDE_CORES=${SHENANGO_EXCLUDE}    \
        ${STATS_CORE_OPT} ${GDBFLAG}                                \
        PROVIDED_CFLAGS="""$SOPTS"""
    popd 

    pushd ${SHENANGO_DIR}/scripts
    gcc cstate.c -o cstate
    popd

    pushd ${SHENANGO_DIR}/shim
    make clean 
    make
    popd
fi

if [[ $SYNTHETIC ]]; then 
    if [[ $ONETIME ]]; then 
        # Install rust
        curl https://sh.rustup.rs -sSf | sh
        source $HOME/.cargo/env
        rustup default nightly-2020-06-06
    fi
    
    pushd ${SHENANGO_DIR}/apps/synthetic
    source $HOME/.cargo/env
    cargo clean
    cargo update
    cargo build --release
    popd
fi

echo "ALL DONE!"

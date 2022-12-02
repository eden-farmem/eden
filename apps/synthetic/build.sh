#
# Build synthetic app for apps like memcached
#

#!/bin/bash
set -e

#
# Build Shenango, Kona and other related app code
#

usage="\n
-d, --debug \t\t build debug\n
-o, --onetime \t\t first time (sets up rust and cargo env)\n
-g, --gdb \t\t build with symbols\n
-h, --help \t\t this usage information message\n"


SCRIPT_PATH=`realpath $0`
SCRIPT_DIR=`dirname ${SCRIPT_PATH}`
SHENANGO_DIR="${SCRIPT_DIR}/../../"

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
# RNIC NUMA node = 1 (good for sc30, sc40)
NUMA_NODE=1

# build simple shenango
pushd ${SHENANGO_DIR} 
make clean
if [[ $GDB ]]; then OPTS="$OPTS GDB=1"; fi
OPTS="$OPTS NUMA_NODE=${NUMA_NODE}"
make all -j ${DEBUG} ${OPTS}
popd

if [[ $ONETIME ]]; then 
    # Install rust
    curl https://sh.rustup.rs -sSf | sh
    source $HOME/.cargo/env
    rustup default nightly-2020-06-06
fi
    
pushd ${SCRIPT_DIR}
source $HOME/.cargo/env
cargo clean
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo update
cargo build --release
popd

echo "ALL DONE!"
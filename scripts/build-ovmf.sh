#!/usr/bin/env bash
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd $SCRIPT_DIR/../edk2

export PYTHON3_ENABLE=TRUE
export PYTHON_COMMAND=python3
export CC=/usr/bin/gcc-7

# First build requires some initialisation
if [ ! -d "$SCRIPT_DIR/../edk2/BaseTools/Source/C/bin" ]; then
    git submodule update --init    
    make -C BaseTools -j $(nproc)
    patch -p1 -i ../ovmf/svsm_edk2.patch
fi

source edksetup.sh BaseTools

build -a X64 -b DEBUG -t GCC5 -D DEBUG_ON_SERIAL_PORT -D DEBUG_VERBOSE -D FD_SVSM -p OvmfPkg/OvmfPkgX64.dsc
cp Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd ../ovmf
popd

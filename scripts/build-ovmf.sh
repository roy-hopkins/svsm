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
    cd OvmfPkg
    ln -s ../../ovmf/OvmfPkg/OvmfPkgSvsmX64.dsc OvmfPkgSvsmX64.dsc
    ln -s ../../ovmf/OvmfPkg/OvmfPkgSvsmX64.fdf OvmfPkgSvsmX64.fdf
    ln -s ../../ovmf/OvmfPkg/SvsmResetVector SvsmResetVector
    cd ..
fi

source edksetup.sh BaseTools

if [ $1 == "debug" ]; then
    build -a X64 -b DEBUG -t GCC5 -D DEBUG_ON_SERIAL_PORT -D DEBUG_VERBOSE -p OvmfPkg/OvmfPkgSvsmX64.dsc
else
    build -a X64 -b RELEASE -t GCC5 -p OvmfPkg/OvmfPkgSvsmX64.dsc
fi
popd

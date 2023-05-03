ifdef RELEASE
TARGET_PATH="release"
CARGO_ARGS="--release"
OVMF_BUILD_ARGS=
OVMF_BUILD_DIR=edk2/Build/OvmfSvsmX64/RELEASE_GCC5/FV
OVMF_OUTPUT_DIR=ovmf/release
else
TARGET_PATH="debug"
CARGO_ARGS=
OVMF_BUILD_ARGS=debug
OVMF_BUILD_DIR=edk2/Build/OvmfSvsmX64/DEBUG_GCC5/FV
OVMF_OUTPUT_DIR=ovmf/debug
endif

STAGE2_ELF = "target/svsm-target/${TARGET_PATH}/stage2"
KERNEL_ELF = "target/svsm-target/${TARGET_PATH}/svsm"

STAGE1_OBJS = stage1/stage1.o stage1/reset.o

all: svsm.bin ovmf/SVSM_CODE.fd

test:
	cd src/
	cargo test --target=x86_64-unknown-linux-gnu -Z build-std

utils/gen_meta: utils/gen_meta.c
	cc -O3 -Wall -o $@ $<

utils/print-meta: utils/print-meta.c
	cc -O3 -Wall -o $@ $<

stage1/meta.bin: utils/gen_meta utils/print-meta
	./utils/gen_meta $@

stage1/stage2.bin:
	cargo build ${CARGO_ARGS} --bin stage2
	objcopy -O binary ${STAGE2_ELF} $@

stage1/kernel.bin:
	cargo build ${CARGO_ARGS} --bin svsm
	objcopy -O binary ${KERNEL_ELF} $@

stage1/stage1.o: stage1/stage1.S stage1/stage2.bin stage1/kernel.bin
stage1/reset.o:  stage1/reset.S stage1/meta.bin

stage1/stage1: ${STAGE1_OBJS}
	$(CC) -o $@ $(STAGE1_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tstage1/stage1.lds

svsm.bin: stage1/stage1
	objcopy -O binary $< $@

ovmf: svsm.bin
	scripts/build-ovmf.sh ${OVMF_BUILD_ARGS}
	mkdir -p ${OVMF_OUTPUT_DIR}
	cp ${OVMF_BUILD_DIR}/OVMF_CODE.fd ${OVMF_BUILD_DIR}/OVMF_VARS.fd ${OVMF_BUILD_DIR}/OVMF.fd ${OVMF_OUTPUT_DIR}

clean:
	cargo clean
	rm -f stage1/stage2.bin svsm.bin stage1/meta.bin ${STAGE1_OBJS} gen_meta ${OVMF_OUTPUT_DIR}/*.fd

.PHONY: stage1/stage2.bin stage1/kernel.bin svsm.bin clean ovmf

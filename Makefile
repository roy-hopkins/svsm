ifdef RELEASE
TARGET_PATH="release"
CARGO_ARGS="--release"
else
TARGET_PATH="debug"
CARGO_ARGS=
endif

STAGE2_ELF = "target/svsm-target/${TARGET_PATH}/stage2"
KERNEL_ELF = "target/svsm-target/${TARGET_PATH}/svsm"

STAGE1_OBJS = stage1/stage1.o stage1/reset.o
SVSM_CODE_OBJS = ovmf/ovmf.o stage1/stage1.o stage1/reset.o

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

ovmf/OVMF_CODE.fd: edk2/OvmfPkg/OvmfPkgX64.dsc
	scripts/build-ovmf.sh

ovmf/ovmf.bin: ovmf/OVMF_CODE.fd
	cp $< $@
	truncate --size=-8K $@
ovmf/ovmf.o: ovmf/ovmf.bin
	objcopy -O elf64-x86-64 -B i386 -I binary --rename-section .data=.ovmf $< $@

ovmf/SVSM_CODE.o: ${SVSM_CODE_OBJS}
	$(CC) -o $@ $(SVSM_CODE_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tovmf/svsm_ovmf.lds

ovmf/SVSM_CODE.fd: ovmf/SVSM_CODE.o
	objcopy -O binary $< $@

clean:
	cargo clean
	rm -f stage1/stage2.bin svsm.bin stage1/meta.bin ${STAGE1_OBJS} gen_meta ${SVSM_CODE_OBJS} ovmf/OVMF_CODE.fd ovmf/ovmf.bin ovmf/ovmf.o ovmf/SVSM_CODE.o ovmf/SVSM_CODE.fd

.PHONY: stage1/stage2.bin stage1/kernel.bin svsm.bin clean

ifdef RELEASE
TARGET_PATH="release"
FEATURES ?= "default"
CARGO_ARGS = --features ${FEATURES}
CARGO_ARGS += --release
else
TARGET_PATH="debug"
FEATURES ?= "default-debug"
CARGO_ARGS = --features ${FEATURES}
endif

ifeq ($(V), 1)
CARGO_ARGS += -v
else ifeq ($(V), 2)
CARGO_ARGS += -vv
endif

STAGE2_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/stage2"
KERNEL_ELF = "target/x86_64-unknown-none/${TARGET_PATH}/svsm"
TEST_KERNEL_ELF = target/x86_64-unknown-none/${TARGET_PATH}/svsm-test
FS_FILE ?= none

C_BIT_POS ?= 51

STAGE1_OBJS = stage1/stage1.o stage1/reset.o
IGVM_FILES = bin/coconut-qemu.igvm bin/coconut-hyperv.igvm
IGVMBLD = bin/igvmbld

all: stage1/kernel.elf svsm.bin igvm

igvm: $(IGVM_FILES)

$(IGVMBLD): igvmbld/igvmbld.c igvmbld/igvm_defs.h igvmbld/sev-snp.h
	mkdir -v -p bin
	$(CC) -o $@ -O -Iigvmbld igvmbld/igvmbld.c

bin/coconut-qemu.igvm: $(IGVMBLD) stage1/kernel.elf stage1/stage2.bin
	$(IGVMBLD) --output $@ --stage2 stage1/stage2.bin --kernel stage1/kernel.elf --qemu

bin/coconut-hyperv.igvm: $(IGVMBLD) stage1/kernel.elf stage1/stage2.bin
	$(IGVMBLD) --output $@ --stage2 stage1/stage2.bin --kernel stage1/kernel.elf --hyperv --com-port 3

test:
	cargo test --target=x86_64-unknown-linux-gnu

test-in-svsm: utils/cbit stage1/test-kernel.elf svsm.bin
	./scripts/test-in-svsm.sh

doc:
	cargo doc --open --all-features --document-private-items

utils/gen_meta: utils/gen_meta.c
	cc -O3 -Wall -o $@ $<

utils/print-meta: utils/print-meta.c
	cc -O3 -Wall -o $@ $<

utils/cbit: utils/cbit.c
	cc -O3 -Wall -o $@ $<

stage1/meta.bin: utils/gen_meta utils/print-meta
	./utils/gen_meta $@

stage1/stage2.bin:
	cargo build ${CARGO_ARGS} --bin stage2
	objcopy -O binary ${STAGE2_ELF} $@

stage1/kernel.elf:
	cargo build ${CARGO_ARGS} --bin svsm
	objcopy -O elf64-x86-64 --strip-unneeded ${KERNEL_ELF} $@

stage1/test-kernel.elf:
	LINK_TEST=1 cargo +nightly test --config 'target.x86_64-unknown-none.runner=["sh", "-c", "cp $$0 ${TEST_KERNEL_ELF}"]'
	objcopy -O elf64-x86-64 --strip-unneeded ${TEST_KERNEL_ELF} stage1/kernel.elf

stage1/svsm-fs.bin:
ifneq ($(FS_FILE), none)
	cp -f $(FS_FILE) stage1/svsm-fs.bin
endif
	touch stage1/svsm-fs.bin

stage1/stage1.o: stage1/stage1.S stage1/stage2.bin stage1/svsm-fs.bin
	cc -c -o $@ stage1/stage1.S

stage1/reset.o:  stage1/reset.S stage1/meta.bin

stage1/stage1: ${STAGE1_OBJS}
	$(CC) -o $@ $(STAGE1_OBJS) -nostdlib -Wl,--build-id=none -Wl,-Tstage1/stage1.lds

svsm.bin: stage1/stage1
	objcopy -O binary $< $@

clean:
	cargo clean
	rm -f stage1/stage2.bin svsm.bin stage1/meta.bin stage1/kernel.elf stage1/stage1 stage1/svsm-fs.bin ${STAGE1_OBJS} utils/gen_meta utils/print-meta
	rm -rf bin

.PHONY: stage1/stage2.bin stage1/kernel.elf stage1/test-kernel.elf svsm.bin clean stage1/svsm-fs.bin test test-in-svsm

BUILD_TARGET = mee knf
BUILD_DIR = ../../build/mcos
SRC = $PWD

KERNEL = kernel.img
KERNELS = $(addsuffix /$(KERNEL),$(addprefix $(BUILD_DIR)/,$(BUILD_TARGET)))

.PHONY: all clean

all: $(KERNELS)

%/kernel.img: %/Makefile
	make -C $(dir $@)

%/Makefile: Makefile.build FORCE
	@mkdir -p $(dir $@)
	@echo 'SRC = $(PWD)' > $@
	@echo 'TARGET = $(notdir $(patsubst %/,%,$(dir $@)))' >> $@
	@cat Makefile.build >> $@

clean: $(addsuffix .clean,$(BUILD_TARGET))

%.clean: $(BUILD_DIR)/%/Makefile
	make -C $(BUILD_DIR)/$(basename $@) clean

FORCE:

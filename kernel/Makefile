BUILD_TARGET = mee knf
SRC = $(CURDIR)

AALBASE ?= $(SRC)/../../aal/manycore
O ?= $(KBUILD_OUTPUT)
V ?= $(VERBOSE)

KERNEL = kernel.img
KERNELS = $(addsuffix /$(KERNEL),$(addprefix $(O)/,$(BUILD_TARGET)))

SUBCMD_OPTS = V='$(V)'

$(if $(O),,$(error Specify the compilation target directory))
$(if $(shell ls $(AALBASE)/Makefile.aal),,\
	$(error AAL is not found in $(AALBASE)))

.PHONY: all clean

all: $(KERNELS)

%/kernel.img: %/Makefile
	@echo 'Building for' $(dir $@)
	@make --no-print-directory -C $(dir $@) $(SUBCMD_OPTS)

%/Makefile: Makefile.build FORCE
	@mkdir -p $(dir $@)
	@echo 'SRC = $(SRC)' > $@
	@echo 'AALBASE = $(AALBASE)' >> $@
	@echo 'TARGET = $(notdir $(patsubst %/,%,$(dir $@)))' >> $@
	@cat Makefile.build >> $@

clean: $(addsuffix .clean,$(BUILD_TARGET))

%.clean: $(O)/%/Makefile
	@make -C $(O)/$(basename $@) $(SUBCMD_OPTS) clean

FORCE:

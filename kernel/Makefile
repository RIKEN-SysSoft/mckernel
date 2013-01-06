#BUILD_TARGET = builtin-mic attached-mic
BUILD_TARGET ?= attached-mic
SRC = $(CURDIR)

IHKBASE ?= $(SRC)/../../ihk/cokernel
O ?= $(KBUILD_OUTPUT)
V ?= $(VERBOSE)

KERNEL = kernel.img
KERNELS = $(addsuffix /$(KERNEL),$(addprefix $(O)/,$(BUILD_TARGET)))

SUBCMD_OPTS = V='$(V)'

$(if $(O),,$(error Specify the compilation target directory))
#$(if $(shell ls $(IHKBASE)/Makefile),,\
#	$(error IHK is not found in $(IHKBASE)))

.PHONY: all clean depend

all: $(KERNELS)

%/kernel.img: %/Makefile
	@echo 'Building for' $(dir $@)
	@make --no-print-directory -C $(dir $@) $(SUBCMD_OPTS)

%/Makefile: Makefile.build FORCE
	@mkdir -p $(dir $@)
	@echo 'SRC = $(SRC)' > $@
	@echo 'IHKBASE = $(IHKBASE)' >> $@
	@echo 'TARGET = $(notdir $(patsubst %/,%,$(dir $@)))' >> $@
	@echo 'TARGETDIR = $$(shell echo $$(TARGET) | sed "s/-/\//")' >> $@
	@cat Makefile.build >> $@
	@rm -f $(dir $@)/Makefile.dep

clean: $(addsuffix .clean,$(BUILD_TARGET))

%.clean: $(O)/%/Makefile
	@make --no-print-directory -C $(O)/$(basename $@) $(SUBCMD_OPTS) clean

FORCE:

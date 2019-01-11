# Makefile COPYRIGHT FUJITSU LIMITED 2018
#
# [own copile]
#  $ make
#
# [cross copile]
#  $ ARCH=${target_arch} CC=${cross_compiler} make
#

# target name.
TARGET := test_contiguous_pte
ARCH   ?= arm64

#---------------
# path settings.
#---------------
# directory.
BIN_DIR       := bin
SRC_ROOT_DIR  := src
DEP_ROOT_DIR  := depend
OBJ_ROOT_DIR  := obj
INC_DIRS      := . $(SRC_ROOT_DIR) $(SRC_ROOT_DIR)/arch/$(ARCH)/include

TP_LOG_DIR  := result

SRC_DIRS := $(shell find $(SRC_ROOT_DIR) -type d | grep -vw $(SRC_ROOT_DIR)/arch) $(shell find $(SRC_ROOT_DIR)/arch/$(ARCH) -type d)
OBJ_DIRS := $(patsubst $(SRC_ROOT_DIR)%, $(OBJ_ROOT_DIR)%, $(SRC_DIRS))
DEP_DIRS := $(patsubst $(SRC_ROOT_DIR)%, $(DEP_ROOT_DIR)%, $(SRC_DIRS))

# file lists.
BIN     := $(TARGET)
PROGRAM := $(BIN_DIR)/$(BIN)
SRCS    := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
OBJS    := $(patsubst $(SRC_ROOT_DIR)%, $(OBJ_ROOT_DIR)%, $(SRCS:.c=.o))
DEPS    := $(patsubst $(SRC_ROOT_DIR)%, $(DEP_ROOT_DIR)%, $(SRCS:.c=.d))

#--------------
# build otions.
#--------------
# compile.
CFLAGS += -g
CFLAGS += -O0
CFLAGS += -Wall
CFLAGS += -Wstrict-prototypes
CFLAGS += -funsigned-char

# preprocess.
CPPFLAGS += $(foreach dir,$(INC_DIRS),-I$(dir))
CPPFLAGS += -D_GNU_SOURCE

# link.
LOADLIBS +=

#--------
# targets
#--------
CC ?= gcc
LD := $(CC)

RM := rm -rf
SED := sed
MKDIR := mkdir -p

# Default target.
all: $(TARGET)

# Generate Program.
$(TARGET): $(OBJS)
	$(MKDIR) $(BIN_DIR)
	$(LD) $(LDFLAGS) $^ $(LOADLIBS) -o $(PROGRAM)

# Remove any generated file.
clean:
	$(RM) $(PROGRAM) $(TP_LOG_DIR)
	-@find $(SRC_ROOT_DIR) -name \*~ -exec $(RM) {} +;
	-@if [ "." != $(BIN_DIR) ]; then \
		$(RM) $(BIN_DIR); \
	fi
	-@if [ "." != $(OBJ_ROOT_DIR) ]; then \
		$(RM) $(OBJ_ROOT_DIR); \
	fi
	-@if [ "." != $(DEP_ROOT_DIR) ]; then \
		$(RM) $(DEP_ROOT_DIR); \
	fi

# Generate object file.
$(OBJS):
	-@ $(MKDIR) $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ -c $(patsubst $(OBJ_ROOT_DIR)%, $(SRC_ROOT_DIR)%, $(@:.o=.c)) \
		-DTEST_SUITE=$(shell echo $@ | sed 's|$(OBJ_ROOT_DIR)/\([^/]*\).*.o|\1|g') \
		-DTEST_NUMBER=$(shell echo $@ | sed 's|$(OBJ_ROOT_DIR)/[^/]*/[0]\{,2\}\([0-9]*\).o|\1|g' | grep -E ^[0-9]+$)

# Generate dependencies file.
$(DEPS):
	-@ $(MKDIR) $(DEP_DIRS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -M $(filter %/$(patsubst $(DEP_ROOT_DIR)%, $(SRC_ROOT_DIR)%, $(@:.d=.c)), $(SRCS)) |\
	$(SED) 's|$(subst .d,.o,$(notdir $@)) *:|$(filter %/$(patsubst $(DEP_ROOT_DIR)%, $(OBJ_ROOT_DIR)%, $(@:.d=.o)), $(OBJS)) : Makefile|' >$@

.PHONY: all clean
ifneq "$(MAKECMDGOALS)" "clean"
 -include $(DEPS)
endif

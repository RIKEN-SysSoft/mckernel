include $(HOME)/.mck_test_config.mk

TARGET=1421

all: $(TARGET)

test: $(TARGET)
	@echo "===== getdents count: 40"
	$(MCK_DIR)/bin/mcexec ./$(TARGET) /sys/devices/system/node 40
	@printf "\n===== getdents count: 200\n"
	$(MCK_DIR)/bin/mcexec ./$(TARGET) /sys/devices/system/node 200

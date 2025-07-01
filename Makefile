# Makefile chính cho Virtual Network Driver v2.0
# Mô tả: Build system cho virtual network driver with enhanced features

# Biến cấu hình
SHELL := /bin/bash
PROJECT_NAME := virtual-network-driver
VERSION := 2.0
BUILD_DIR := build
LOG_DIR := logs
TEST_LOG := $(LOG_DIR)/test.log

# Màu sắc cho output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Targets mặc định
.DEFAULT_GOAL := help

# Tạo thư mục cần thiết
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(LOG_DIR):
	@mkdir -p $(LOG_DIR)

# Help target - hiển thị các lệnh có sẵn
help: ## Hiển thị menu help
	@echo -e "$(GREEN)=======================================$(NC)"
	@echo -e "$(GREEN)Virtual Network Driver v$(VERSION) - Build System$(NC)"
	@echo -e "$(GREEN)=======================================$(NC)"
	@echo ""
	@echo "Các lệnh có sẵn:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(GREEN)Ví dụ sử dụng:$(NC)"
	@echo "  make all          # Biên dịch tất cả modules"
	@echo "  make test         # Chạy kiểm thử đầy đủ"
	@echo "  make install      # Cài đặt modules"
	@echo "  make clean        # Dọn dẹp build files"
	@echo ""

# Build tất cả modules
all: $(BUILD_DIR) ## Biên dịch tất cả modules
	@echo -e "$(GREEN)🔨 Bắt đầu biên dịch modules...$(NC)"
	@$(MAKE) -C src all
	@echo -e "$(GREEN)✅ Biên dịch hoàn thành!$(NC)"

# Build chỉ driver module
driver: $(BUILD_DIR) ## Biên dịch chỉ driver module
	@echo -e "$(GREEN)🔨 Biên dịch driver module...$(NC)"
	@$(MAKE) -C src vnet_driver.ko
	@echo -e "$(GREEN)✅ Driver module biên dịch xong!$(NC)"

# Build chỉ netfilter module
netfilter: $(BUILD_DIR) ## Biên dịch chỉ netfilter module
	@echo -e "$(GREEN)🔨 Biên dịch netfilter module...$(NC)"
	@$(MAKE) -C src vnet_netfilter.ko
	@echo -e "$(GREEN)✅ Netfilter module biên dịch xong!$(NC)"

# Chạy test tự động
test: $(LOG_DIR) ## Chạy kiểm thử đầy đủ
	@echo -e "$(GREEN)🧪 Bắt đầu test suite...$(NC)"
	@if [ -f "./test_driver.sh" ]; then \
		sudo ./test_driver.sh 2>&1 | tee $(TEST_LOG); \
		echo -e "$(GREEN)📊 Test log được lưu tại: $(TEST_LOG)$(NC)"; \
	else \
		echo -e "$(RED)❌ Không tìm thấy test script!$(NC)"; \
		exit 1; \
	fi

# Test nhanh (không có stress test)
test-quick: $(LOG_DIR) ## Chạy test nhanh (bỏ qua stress test)
	@echo -e "$(GREEN)⚡ Chạy quick test...$(NC)"
	@if [ -f "./test_driver.sh" ]; then \
		sudo timeout 300 ./test_driver.sh 2>&1 | tee $(TEST_LOG); \
	else \
		echo -e "$(RED)❌ Không tìm thấy test script!$(NC)"; \
		exit 1; \
	fi

# Load modules mà không cài đặt
load: all ## Load modules vào kernel
	@echo -e "$(GREEN)🔄 Load modules vào kernel...$(NC)"
	@if [ ! -f "src/vnet_driver.ko" ] || [ ! -f "src/vnet_netfilter.ko" ]; then \
		echo -e "$(RED)❌ Modules chưa được biên dịch! Chạy 'make all' trước.$(NC)"; \
		exit 1; \
	fi
	@echo -e "$(YELLOW)⚠️ Cần quyền root để load modules$(NC)"
	sudo insmod src/vnet_driver.ko
	sudo insmod src/vnet_netfilter.ko
	@echo -e "$(GREEN)✅ Modules đã được load!$(NC)"
	@echo -e "$(GREEN)📊 Kiểm tra: lsmod | grep vnet$(NC)"

# Unload modules
unload: ## Unload modules khỏi kernel
	@echo -e "$(GREEN)🔄 Unload modules khỏi kernel...$(NC)"
	@echo -e "$(YELLOW)⚠️ Cần quyền root để unload modules$(NC)"
	-sudo rmmod vnet_netfilter 2>/dev/null || echo "vnet_netfilter không được load"
	-sudo rmmod vnet_driver 2>/dev/null || echo "vnet_driver không được load"
	@echo -e "$(GREEN)✅ Modules đã được unload!$(NC)"

# Reload modules (unload + load)
reload: unload load ## Reload modules (unload + load)
	@echo -e "$(GREEN)🔄 Modules đã được reload!$(NC)"

# Dọn dẹp build files
clean: ## Dọn dẹp file biên dịch
	@echo -e "$(GREEN)🧹 Dọn dẹp build files...$(NC)"
	@$(MAKE) -C src clean
	@rm -rf $(BUILD_DIR)
	@rm -rf $(LOG_DIR)
	@rm -f *.log
	@echo -e "$(GREEN)✅ Dọn dẹp hoàn thành!$(NC)"

# Kiểm tra môi trường development
check-env: ## Kiểm tra môi trường development
	@echo -e "$(GREEN)🔍 Kiểm tra môi trường development...$(NC)"
	@echo ""
	@echo "Kernel version:"
	@uname -r
	@echo ""
	@echo "Kernel headers:"
	@if [ -d "/lib/modules/$(shell uname -r)/build" ]; then \
		echo -e "$(GREEN)✅ Kernel headers tồn tại$(NC)"; \
	else \
		echo -e "$(RED)❌ Kernel headers không tồn tại$(NC)"; \
		echo -e "$(YELLOW)Cài đặt: sudo apt-get install linux-headers-$(shell uname -r)$(NC)"; \
	fi
	@echo ""
	@echo "Build tools:"
	@which gcc >/dev/null 2>&1 && echo -e "$(GREEN)✅ GCC tồn tại$(NC)" || echo -e "$(RED)❌ GCC không tồn tại$(NC)"
	@which make >/dev/null 2>&1 && echo -e "$(GREEN)✅ Make tồn tại$(NC)" || echo -e "$(RED)❌ Make không tồn tại$(NC)"
	@echo ""
	@echo "Network tools:"
	@which nc >/dev/null 2>&1 && echo -e "$(GREEN)✅ Netcat tồn tại$(NC)" || echo -e "$(RED)❌ Netcat không tồn tại$(NC)"
	@which ip >/dev/null 2>&1 && echo -e "$(GREEN)✅ iproute2 tồn tại$(NC)" || echo -e "$(RED)❌ iproute2 không tồn tại$(NC)"

# Hiển thị trạng thái modules
status: ## Hiển thị trạng thái modules
	@echo -e "$(GREEN)📊 Trạng thái modules:$(NC)"
	@echo ""
	@echo "Loaded modules:"
	@lsmod | grep -E 'vnet_driver|vnet_netfilter' || echo "Không có vnet modules nào được load"
	@echo ""
	@echo "Network interfaces:"
	@ip link show | grep -E 'vnet[0-9]' || echo "Không có vnet interfaces nào"
	@echo ""
	@echo "Proc files:"
	@ls -la /proc/vnet_* 2>/dev/null || echo "Không có proc files nào"

# Hiển thị kernel logs liên quan
show-logs: ## Hiển thị kernel logs liên quan
	@echo -e "$(GREEN)📋 Kernel logs liên quan tới vnet:$(NC)"
	@echo ""
	@dmesg | grep -E 'vnet|netfilter_capture' | tail -20 || echo "Không có logs nào"

# Hiển thị packet capture statistics
capture: ## Hiển thị packet capture statistics
	@echo -e "$(GREEN)📈 Packet capture statistics:$(NC)"
	@echo ""
	@if [ -f "/proc/vnet_capture" ]; then \
		cat /proc/vnet_capture; \
	else \
		echo "Packet capture không khả dụng"; \
	fi

# Debug mode build
debug: ## Biên dịch với debug mode
	@echo -e "$(GREEN)🐛 Biên dịch với debug mode...$(NC)"
	@$(MAKE) -C src clean
	@$(MAKE) -C src EXTRA_CFLAGS="-DDEBUG -g" all
	@echo -e "$(GREEN)✅ Debug build hoàn thành!$(NC)"

# Phony targets
.PHONY: help all driver netfilter test test-quick load unload reload clean check-env status show-logs capture debug
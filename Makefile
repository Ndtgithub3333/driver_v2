# Thu gọn Makefile cho Virtual Network Driver v2.0

SHELL := /bin/bash
PROJECT_NAME := virtual-network-driver
VERSION := 2.0
LOG_DIR := logs
TEST_LOG := $(LOG_DIR)/test.log

# Màu sắc
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m

.DEFAULT_GOAL := help

$(LOG_DIR):
	@mkdir -p $(LOG_DIR)

# Thu gọn help
help: ## Hiển thị menu help
	@echo -e "$(GREEN)Virtual Network Driver v$(VERSION)$(NC)"
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

# Thu gọn build targets
all: ## Build modules
	@$(MAKE) -C src all

load: all ## Load modules vào kernel
	@sudo insmod src/vnet_driver.ko && sudo insmod src/vnet_netfilter.ko

unload: ## Unload modules
	@sudo rmmod vnet_netfilter 2>/dev/null || true
	@sudo rmmod vnet_driver 2>/dev/null || true

reload: unload load ## Reload modules

clean: ## Dọn dẹp files
	@$(MAKE) -C src clean
	@rm -rf $(LOG_DIR)

test: $(LOG_DIR) ## Chạy test đầy đủ
	@sudo ./test_driver.sh 2>&1 | tee $(TEST_LOG)

status: ## Hiển thị trạng thái hệ thống
	@echo "Modules loaded:"
	@lsmod | grep vnet || echo "No vnet modules loaded"
	@echo "Interfaces:"
	@ip link show | grep vnet || echo "No vnet interfaces"

.PHONY: help all load unload reload clean test status
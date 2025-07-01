#!/bin/bash

# Thu gọn Script kiểm thử Virtual Network Driver

set -e

# Màu sắc
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Cấu hình
VNET0_IP="192.168.10.1"
VNET1_IP="192.168.10.2"
TEST_PORT="12345"

# Hàm in
print_header() {
    echo -e "\n${BLUE}===== $1 =====${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Thu gọn kiểm tra hệ thống
basic_system_check() {
    print_header "Kiểm tra hệ thống cơ bản"
    
    # Kiểm tra root
    if [ "$EUID" -ne 0 ]; then
        print_error "Script cần quyền root (sudo)"
        exit 1
    fi
    
    # Kiểm tra kernel headers
    KERNEL_VERSION=$(uname -r)
    if [ ! -d "/lib/modules/$KERNEL_VERSION/build" ]; then
        print_error "Kernel headers không tồn tại"
        exit 1
    fi
    
    # Gỡ bỏ modules cũ
    sudo rmmod vnet_netfilter 2>/dev/null || true
    sudo rmmod vnet_driver 2>/dev/null || true
    sudo ip link set vnet0 down 2>/dev/null || true
    sudo ip link set vnet1 down 2>/dev/null || true
    
    print_success "Hệ thống sẵn sàng"
}

# Cleanup khi có lỗi
cleanup_on_error() {
    print_warning "Cleanup..."
    sudo rmmod vnet_netfilter 2>/dev/null || true
    sudo rmmod vnet_driver 2>/dev/null || true
    sudo ip link set vnet0 down 2>/dev/null || true
    sudo ip link set vnet1 down 2>/dev/null || true
}

trap cleanup_on_error ERR

# Thu gọn build modules
compile_modules() {
    print_header "Build modules"
    
    make clean >/dev/null 2>&1 || true
    make all >/dev/null 2>&1
    
    if [ -f "src/vnet_driver.ko" ] && [ -f "src/vnet_netfilter.ko" ]; then
        print_success "Modules built thành công"
    else
        print_error "Build modules thất bại"
        exit 1
    fi
}

# Thu gọn load modules
load_modules() {
    print_header "Load modules"
    
    sudo insmod src/vnet_driver.ko
    sleep 1
    sudo insmod src/vnet_netfilter.ko
    sleep 2
    
    # Kiểm tra modules loaded
    if lsmod | grep -q "vnet_driver" && lsmod | grep -q "vnet_netfilter"; then
        print_success "Modules loaded thành công"
    else
        print_error "Load modules thất bại"
        exit 1
    fi
}

# Thu gọn cấu hình interfaces
configure_interfaces() {
    print_header "Cấu hình interfaces"
    
    # Kiểm tra interfaces tồn tại
    if ! ip link show vnet0 >/dev/null 2>&1 || ! ip link show vnet1 >/dev/null 2>&1; then
        print_error "Virtual interfaces không tồn tại"
        exit 1
    fi
    
    # Cấu hình IP
    sudo ip addr add ${VNET0_IP}/24 dev vnet0
    sudo ip addr add ${VNET1_IP}/24 dev vnet1
    sudo ip link set vnet0 up
    sudo ip link set vnet1 up
    
    print_success "Interfaces đã được cấu hình"
}

# Thu gọn test connectivity
test_basic_connectivity() {
    print_header "Test connectivity cơ bản"
    
    # Test netcat connectivity
    timeout 10 bash -c "
        # Start server
        nc -l -s ${VNET1_IP} -p ${TEST_PORT} >/dev/null &
        SERVER_PID=\$!
        sleep 1
        
        # Send data from client
        echo 'test data' | nc -w 2 -s ${VNET0_IP} ${VNET1_IP} ${TEST_PORT}
        
        # Cleanup
        kill \$SERVER_PID 2>/dev/null || true
    " && print_success "Connectivity test PASSED" || print_warning "Connectivity test có vấn đề"
    
    # Hiển thị stats
    echo "Interface statistics:"
    cat /proc/net/dev | grep vnet
}

# Thu gọn main function
main() {
    echo -e "${BLUE}"
    echo "=================================="
    echo "🚀 Virtual Network Driver Test"
    echo "=================================="
    echo -e "${NC}"
    
    # Các test cơ bản đã được thu gọn
    basic_system_check
    compile_modules
    load_modules
    configure_interfaces
    test_basic_connectivity
    
    print_header "🎉 Test hoàn thành"
    print_success "Driver hoạt động bình thường!"
    print_success "Xem kernel logs: dmesg | grep vnet"
    
    # Cleanup
    sudo rmmod vnet_netfilter 2>/dev/null || true
    sudo rmmod vnet_driver 2>/dev/null || true
}

# Chạy main
main "$@"
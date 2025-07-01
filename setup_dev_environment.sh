#!/bin/bash

# Script thiết lập môi trường development cho Virtual Network Driver
# Mô tả: Tự động cài đặt dependencies và cấu hình môi trường

set -e

# Màu sắc
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}=====================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=====================================${NC}"
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

# Kiểm tra quyền root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Script này cần quyền root. Chạy: sudo $0"
        exit 1
    fi
}

# Phát hiện distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        print_error "Không thể phát hiện distribution"
        exit 1
    fi
    
    print_success "Phát hiện: $PRETTY_NAME"
}

# Cài đặt dependencies cho Ubuntu/Debian
install_ubuntu_deps() {
    print_header "Cài đặt dependencies cho Ubuntu/Debian"
    
    # Update package list
    apt-get update
    
    # Cài đặt kernel headers
    KERNEL_VERSION=$(uname -r)
    apt-get install -y linux-headers-${KERNEL_VERSION}
    print_success "Đã cài đặt kernel headers"
    
    # Cài đặt build tools
    apt-get install -y build-essential
    print_success "Đã cài đặt build tools"
    
    # Cài đặt network tools
    apt-get install -y iproute2 netcat-openbsd iptables
    print_success "Đã cài đặt network tools"
    
    # Cài đặt debugging tools
    apt-get install -y gdb strace tcpdump wireshark-common
    print_success "Đã cài đặt debugging tools"
    
    # Cài đặt documentation tools
    apt-get install -y man-db manpages-dev
    print_success "Đã cài đặt documentation tools"
}

# Thu gọn function setup permissions
setup_ubuntu_environment() {
    print_header "Thiết lập môi trường Ubuntu"
    
    # Kết hợp permission và kernel setup
    if [ -n "$SUDO_USER" ]; then
        usermod -a -G adm "$SUDO_USER" 2>/dev/null || true
    fi
    
    # Cấu hình kernel parameters cần thiết
    cat > /etc/sysctl.d/99-vnet-driver.conf << EOF
# Virtual Network Driver Configuration
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
    
    sysctl -p /etc/sysctl.d/99-vnet-driver.conf
    print_success "Đã cấu hình môi trường Ubuntu"
}

# Thu gọn aliases 
create_aliases() {
    print_header "Tạo aliases hữu ích"
    
    ALIAS_FILE="/etc/profile.d/vnet-aliases.sh"
    
    cat > "$ALIAS_FILE" << 'EOF'
# Virtual Network Driver Aliases
alias vnet-build='cd /opt/vnet-driver && make all'
alias vnet-test='cd /opt/vnet-driver && sudo make test'
alias vnet-status='cd /opt/vnet-driver && make status'
alias vnet-logs='dmesg | grep vnet | tail -20'
alias vnet-clean='cd /opt/vnet-driver && make clean'
EOF
    
    chmod +x "$ALIAS_FILE"
    print_success "Đã tạo aliases đơn giản"
}

# Tạo development scripts
create_dev_scripts() {
    print_header "Tạo development scripts"
    
    # Script debug
    cat > /usr/local/bin/vnet-debug << 'EOF'
#!/bin/bash
# Debug script cho Virtual Network Driver

echo "=== Virtual Network Driver Debug Information ==="
echo "Kernel version: $(uname -r)"
echo "Date: $(date)"
echo ""

echo "=== Loaded Modules ==="
lsmod | grep -E 'vnet_driver|vnet_netfilter' || echo "No vnet modules loaded"
echo ""

echo "=== Network Interfaces ==="
ip link show | grep -E 'vnet[0-9]' || echo "No vnet interfaces"
echo ""

echo "=== Recent Kernel Messages ==="
dmesg | grep -E 'vnet|netfilter_capture' | tail -10 || echo "No kernel messages"
echo ""

echo "=== Packet Capture Statistics ==="
head -15 /proc/vnet_capture 2>/dev/null || echo "Packet capture not available"
echo ""

echo "=== Network Statistics ==="
cat /proc/net/dev | grep vnet || echo "No vnet statistics"
EOF
    
    chmod +x /usr/local/bin/vnet-debug
    print_success "Đã tạo debug script: vnet-debug"
    
    # Script quick test
    cat > /usr/local/bin/vnet-quicktest << 'EOF'
#!/bin/bash
# Quick test script cho Virtual Network Driver

set -e

echo "🚀 Quick test cho Virtual Network Driver"

# Load modules
echo "Loading modules..."
cd /opt/vnet-driver
make load

# Cấu hình interfaces
echo "Configuring interfaces..."
ip addr add 192.168.10.1/24 dev vnet0
ip addr add 192.168.10.2/24 dev vnet1
ip link set vnet0 up
ip link set vnet1 up

# Quick connectivity test
echo "Testing connectivity..."
timeout 5 nc -l -s 192.168.10.2 -p 12345 >/dev/null &
sleep 1
echo "test" | nc -w 2 -s 192.168.10.1 192.168.10.2 12345

echo "✅ Quick test completed!"
echo "📊 View capture: cat /proc/vnet_capture"
EOF
    
    chmod +x /usr/local/bin/vnet-quicktest
    print_success "Đã tạo quick test script: vnet-quicktest"
}

# Validate installation
validate_installation() {
    print_header "Validate installation"
    
    # Kiểm tra kernel headers
    KERNEL_VERSION=$(uname -r)
    if [ -d "/lib/modules/$KERNEL_VERSION/build" ]; then
        print_success "Kernel headers OK"
    else
        print_error "Kernel headers missing"
    fi
    
    # Kiểm tra build tools
    for tool in gcc make; do
        if command -v $tool >/dev/null 2>&1; then
            print_success "$tool OK"
        else
            print_error "$tool missing"
        fi
    done
    
    # Kiểm tra network tools
    for tool in ip nc; do
        if command -v $tool >/dev/null 2>&1; then
            print_success "$tool OK"
        else
            print_error "$tool missing"
        fi
    done
    
    print_success "Validation completed"
}

# Thu gọn main function - chỉ hỗ trợ Ubuntu
main() {
    echo -e "${BLUE}"
    echo "================================="
    echo "🔧 Virtual Network Driver Setup"
    echo "================================="
    echo -e "${NC}"
    
    check_root
    detect_distro
    
    if [[ "$DISTRO" != "ubuntu" && "$DISTRO" != "debian" ]]; then
        print_error "Chỉ hỗ trợ Ubuntu/Debian"
        exit 1
    fi
    
    install_ubuntu_deps
    setup_ubuntu_environment
    create_aliases
    create_dev_scripts
    validate_installation
    
    print_header "🎉 Setup Complete"
    print_success "Development environment đã được thiết lập!"
    print_success "Chạy: make all && make test"
}

# Run main function
main "$@"
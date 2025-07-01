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

# Cài đặt dependencies cho CentOS/RHEL/Fedora
install_rhel_deps() {
    print_header "Cài đặt dependencies cho RHEL/CentOS/Fedora"
    
    # Xác định package manager
    if command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MGR="yum"
    else
        print_error "Không tìm thấy package manager"
        exit 1
    fi
    
    # Cài đặt kernel headers
    KERNEL_VERSION=$(uname -r)
    $PKG_MGR install -y kernel-headers-${KERNEL_VERSION} kernel-devel-${KERNEL_VERSION}
    print_success "Đã cài đặt kernel headers"
    
    # Cài đặt build tools
    $PKG_MGR groupinstall -y "Development Tools"
    print_success "Đã cài đặt build tools"
    
    # Cài đặt network tools
    $PKG_MGR install -y iproute2 nc iptables
    print_success "Đã cài đặt network tools"
    
    # Cài đặt debugging tools
    $PKG_MGR install -y gdb strace tcpdump
    print_success "Đã cài đặt debugging tools"
}

# Thiết lập permissions
setup_permissions() {
    print_header "Thiết lập permissions"
    
    # Thêm user vào nhóm có thể sử dụng netcat
    if [ -n "$SUDO_USER" ]; then
        usermod -a -G adm "$SUDO_USER" 2>/dev/null || true
        print_success "Đã thêm user $SUDO_USER vào group adm"
    fi
    
    # Thiết lập permissions cho proc filesystem
    chmod 644 /proc/sys/net/core/* 2>/dev/null || true
    print_success "Đã thiết lập permissions cho networking"
}

# Cấu hình kernel parameters
configure_kernel() {
    print_header "Cấu hình kernel parameters"
    
    # Tạo file cấu hình
    cat > /etc/sysctl.d/99-vnet-driver.conf << EOF
# Virtual Network Driver Configuration
# Tăng buffer sizes cho network
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 5000

# Enable IP forwarding
net.ipv4.ip_forward = 1

# Disable reverse path filtering cho virtual interfaces
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF
    
    # Apply cấu hình
    sysctl -p /etc/sysctl.d/99-vnet-driver.conf
    print_success "Đã cấu hình kernel parameters"
}

# Tạo systemd service (optional)
create_systemd_service() {
    print_header "Tạo systemd service (optional)"
    
    read -p "Bạn có muốn tạo systemd service để auto-load modules không? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > /etc/systemd/system/vnet-driver.service << 'EOF'
[Unit]
Description=Virtual Network Driver
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'cd /opt/vnet-driver && make load'
ExecStop=/bin/bash -c 'cd /opt/vnet-driver && make unload'
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        print_success "Đã tạo systemd service: vnet-driver.service"
        print_warning "Sử dụng: systemctl enable vnet-driver để auto-start"
    else
        print_warning "Bỏ qua tạo systemd service"
    fi
}

# Tạo aliases hữu ích
create_aliases() {
    print_header "Tạo aliases hữu ích"
    
    ALIAS_FILE="/etc/profile.d/vnet-aliases.sh"
    
    cat > "$ALIAS_FILE" << 'EOF'
# Virtual Network Driver Aliases
alias vnet-build='cd /opt/vnet-driver && make all'
alias vnet-test='cd /opt/vnet-driver && sudo make test'
alias vnet-load='cd /opt/vnet-driver && sudo make load'
alias vnet-unload='cd /opt/vnet-driver && sudo make unload'
alias vnet-status='cd /opt/vnet-driver && make status'
alias vnet-logs='dmesg | grep -E "vnet|netfilter_capture" | tail -20'
alias vnet-capture='cat /proc/vnet_capture 2>/dev/null || echo "Capture not available"'
alias vnet-clean='cd /opt/vnet-driver && make clean'
EOF
    
    chmod +x "$ALIAS_FILE"
    print_success "Đã tạo aliases tại: $ALIAS_FILE"
    print_warning "Restart shell hoặc chạy: source $ALIAS_FILE"
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

# Main function
main() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "🔧 Virtual Network Driver Development Setup"
    echo "=================================================="
    echo -e "${NC}"
    
    check_root
    detect_distro
    
    case $DISTRO in
        ubuntu|debian)
            install_ubuntu_deps
            ;;
        centos|rhel|fedora)
            install_rhel_deps
            ;;
        *)
            print_warning "Unsupported distribution: $DISTRO"
            print_warning "Manually install: kernel-headers, build-essential, netcat, iproute2"
            ;;
    esac
    
    setup_permissions
    configure_kernel
    create_systemd_service
    create_aliases
    create_dev_scripts
    validate_installation
    
    print_header "🎉 Setup Complete"
    print_success "Development environment đã được thiết lập!"
    print_warning "Restart shell để sử dụng aliases"
    print_warning "Available commands:"
    echo "  vnet-build      # Build modules"
    echo "  vnet-test       # Run tests"
    echo "  vnet-debug      # Debug information"
    echo "  vnet-quicktest  # Quick functionality test"
    echo ""
    print_success "Bây giờ bạn có thể chạy: make all && make test"
}

# Run main function
main "$@"
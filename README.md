# Linux Virtual Network Driver - Mô phỏng 2 Network Interface

## 📋 Tổng quan Project

Project này implement một Linux kernel driver tạo ra 2 virtual network interface (`vnet0` và `vnet1`) cho phép truyền packet từ interface này sang interface kia trên cùng một host. Driver sử dụng netfilter framework để bắt và phân tích các gói tin đi qua.

## 🎯 Mục tiêu Project

- **Mục tiêu chính**: Xây dựng Linux driver mô phỏng 2 network interface
- **Chức năng core**: Truyền packet từ interface A (vnet0) tới interface B (vnet1)
- **Công cụ giám sát**: Sử dụng netfilter để capture và phân tích packets
- **Ứng dụng**: Học tập về Linux kernel programming và network stack

## 🏗️ Kiến trúc System

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   User App  │    │   User App  │    │ Monitoring  │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    vnet0    │◄──►│    vnet1    │    │  /proc/net  │
│  Interface  │    │  Interface  │    │   Stats     │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           ▼
                 ┌─────────────────┐
                 │  vnet_driver.ko │
                 │   (Main Driver) │
                 └─────────────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │  vnet_netfilter.ko  │
                │  (Packet Capture)   │
                └─────────────────────┘
                           │
                           ▼
                 ┌─────────────────┐
                 │  Linux Kernel   │
                 │  Network Stack  │
                 └─────────────────┘
```

## 📁 Cấu trúc Directory

```
driver_v2/
├── README.md                          # Tài liệu project này  
├── Makefile                           # Build system chính (root level)
├── setup_dev_environment.sh           # Script thiết lập môi trường development
├── test_driver.sh                     # Script test tự động đầy đủ
├── include/                           # Header files
│   └── vnet_driver.h                  # Definitions và declarations chính
├── src/                               # Source code và build location
│   ├── Makefile                       # Build configuration cho kernel modules
│   ├── vnet_driver.c                  # Main driver module source code
│   ├── vnet_netfilter.c               # Netfilter capture module source code
│   ├── vnet_driver.ko                 # Compiled main driver module (sau khi build)
│   ├── vnet_netfilter.ko              # Compiled netfilter module (sau khi build)
│   ├── *.o                           # Object files (tạm thời sau khi build)
│   ├── *.mod.*                       # Module metadata files (tạm thời)
│   └── Module.symvers                 # Symbol version info (tạm thời)
└── logs/                              # Logs được tạo khi chạy tests
    └── test.log                       # Test execution logs (tạo khi chạy make test)
```

**Ghi chú quan trọng về cấu trúc:**
- **Thư mục `build/`**: Được định nghĩa trong Makefile nhưng không được sử dụng thực tế. Các file `.ko` được build trực tiếp trong `src/`
- **Thư mục `logs/`**: Chỉ chứa `test.log` khi chạy test, không có các log files khác
- **Files build output**: Tất cả được tạo trong `src/` directory bao gồm `.ko`, `.o`, `.mod.*` files

## 🔧 Các Component Chính

### 1. Root Makefile (`./Makefile`)
```makefile
# Makefile chính cho Virtual Network Driver v2.0
# Mô tả: Build system cho virtual network driver with enhanced features

# Biến cấu hình
SHELL := /bin/bash
PROJECT_NAME := virtual-network-driver
VERSION := 2.0
BUILD_DIR := build      # Được định nghĩa nhưng không sử dụng thực tế
LOG_DIR := logs         # Chỉ chứa test.log
TEST_LOG := $(LOG_DIR)/test.log

# Targets chính
all: $(BUILD_DIR)       ## Biên dịch tất cả modules (output vào src/)
test: $(LOG_DIR)        ## Chạy kiểm thử đầy đủ (tạo logs/test.log)
load: all              ## Load modules vào kernel (từ src/*.ko)
unload:                ## Unload modules khỏi kernel
clean:                 ## Dọn dẹp build files (trong src/ và logs/)
```

**Chức năng thực tế:**
- Quản lý build process bằng cách gọi `$(MAKE) -C src`
- Tự động tạo thư mục `logs/` khi cần
- Build output thực tế nằm trong `src/` directory
- `make clean` sẽ xóa files trong `src/` và `logs/`

### 2. Setup Script (`./setup_dev_environment.sh`)
```bash
#!/bin/bash
# Script thiết lập môi trường development cho Virtual Network Driver
# Mô tả: Tự động cài đặt dependencies và cấu hình môi trường

# Các chức năng chính:
detect_distro()         # Phát hiện Linux distribution (Ubuntu/CentOS/Fedora)
install_ubuntu_deps()   # Cài đặt dependencies cho Ubuntu/Debian
install_rhel_deps()     # Cài đặt dependencies cho CentOS/RHEL/Fedora
setup_permissions()     # Thiết lập permissions cho network operations
configure_kernel()      # Cấu hình kernel parameters cho networking
create_systemd_service() # Tạo systemd service (optional)
create_aliases()        # Tạo shell aliases tiện lợi (vnet-build, vnet-test, etc.)
create_dev_scripts()    # Tạo các utility scripts (/usr/local/bin/vnet-debug)
validate_installation() # Validate setup completion
```

**Chức năng thực tế:**
- Cross-platform support cho Ubuntu, CentOS, Fedora
- Cài đặt kernel headers, build tools, network tools tự động
- Tạo aliases hữu ích: `vnet-build`, `vnet-test`, `vnet-debug`, `vnet-logs`
- Thiết lập kernel parameters cho network performance

### 3. Main Driver (`src/vnet_driver.c`)
```c
#include "../include/vnet_driver.h"
#include <linux/version.h>
#include <linux/etherdevice.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student - Ndtgithub3333");
MODULE_DESCRIPTION("Virtual Network Driver with Packet Capture - Fixed Version");
MODULE_VERSION("2.0");

/* Biến toàn cục - được export để netfilter module có thể sử dụng */
struct net_device *vnet_devices[2];        // Mảng chứa 2 network devices
struct list_head captured_packets;         // Danh sách packets đã capture
spinlock_t capture_lock;                   // Lock cho captured packets list thread-safe
int packet_count = 0;                      // Đếm số packets hiện tại

/* Atomic counters để tracking performance một cách thread-safe */
static atomic_t total_packets_sent = ATOMIC_INIT(0);
static atomic_t total_packets_received = ATOMIC_INIT(0);

/* Network operations callbacks - các hàm chính cho network device */
static const struct net_device_ops vnet_netdev_ops = {
    .ndo_open       = vnet_open,        // Hàm mở interface
    .ndo_stop       = vnet_close,       // Hàm đóng interface  
    .ndo_start_xmit = vnet_start_xmit,  // Hàm truyền packet (core function)
    .ndo_get_stats  = vnet_get_stats,   // Hàm lấy statistics
};
```

**Chức năng chính:**
- Tạo và đăng ký 2 virtual network interfaces (vnet0, vnet1)
- Implement packet forwarding logic giữa vnet0 ↔ vnet1
- Quản lý device states và network statistics
- Thread-safe packet processing với spinlocks và atomic counters
- Comprehensive error handling và validation cho tất cả operations

### 4. Netfilter Module (`src/vnet_netfilter.c`)
```c
#include "../include/vnet_driver.h"
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/* Hook function để capture packets - không block packet flow */
static unsigned int vnet_netfilter_hook(void *priv,
                                       struct sk_buff *skb,
                                       const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    char interface_name[IFNAMSIZ];
    char direction[32];
    
    // Validate SKB và extract interface information
    if (!skb || !skb->dev) {
        return NF_ACCEPT;  // Cho phép packet tiếp tục nếu invalid
    }
    
    // Chỉ capture packets từ vnet interfaces
    if (strncmp(skb->dev->name, "vnet", 4) != 0) {
        return NF_ACCEPT;  // Skip non-vnet interfaces
    }
    
    // Validate IP header trước khi analyze
    if (!validate_skb_and_ip_header(skb)) {
        return NF_ACCEPT;  // Skip invalid IP packets
    }
    
    // Phân tích và lưu trữ packet information cho debugging
    analyze_and_store_packet(skb, skb->dev->name, direction);
    
    return NF_ACCEPT;  // Luôn cho phép packet tiếp tục (monitoring only)
}
```

**Chức năng chính:**
- Hook vào Linux network stack để monitor packets
- Chỉ capture packets từ vnet interfaces (vnet0, vnet1)
- Phân tích packet headers (IP, TCP, UDP) với comprehensive validation
- Lưu trữ packet metadata trong `/proc/vnet_capture` để debugging
- Không can thiệp vào packet flow (pure monitoring)

### 5. Build System (`src/Makefile`)
```makefile
# Makefile trong thư mục src cho kernel modules
# Thêm cờ debug để enable debugging trong development
EXTRA_CFLAGS += -DDEBUG

# Định nghĩa các modules cần build
obj-m := vnet_driver.o vnet_netfilter.o

# Kernel build directory - tự động detect kernel version
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Target chính - build tất cả modules
all:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

# Target cleanup - xóa tất cả build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

**Chức năng thực tế:**
- Build kernel modules `.ko` trực tiếp trong thư mục `src/`
- Enable debug flags với `-DDEBUG` cho development
- Integration với Linux kernel build system
- Tự động detect kernel version và headers path
- Clean target xóa tất cả temporary files (`.o`, `.mod.*`, etc.)

### 6. Shared Structures (`include/vnet_driver.h`)
```c
#ifndef VNET_DRIVER_H
#define VNET_DRIVER_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>

/* Định nghĩa constants - Hằng số cấu hình cho driver */
#define VNET_DEVICE_NAME_A "vnet0"         // Tên interface đầu tiên
#define VNET_DEVICE_NAME_B "vnet1"         // Tên interface thứ hai
#define VNET_MAX_PACKET_SIZE 1500          // Kích thước packet tối đa (MTU standard)
#define VNET_STATS_PROC_NAME "vnet_stats"  // Tên file proc cho statistics

/* Private data cho mỗi network device - quản lý state */
struct vnet_priv {
    struct net_device *peer;         // Device peer (vnet0 <-> vnet1 relationship)
    struct net_device_stats stats;   // Standard network statistics (tx_packets, rx_bytes, etc.)
    spinlock_t lock;                 // Thread synchronization cho data protection
    int id;                         // Device identifier (0 cho vnet0, 1 cho vnet1)
    char name[IFNAMSIZ];           // Device name string
    unsigned long last_tx_jiffies;  // Timestamp của last transmission (for monitoring)
    unsigned long last_rx_jiffies;  // Timestamp của last receive (for monitoring)
    bool is_active;                // Trạng thái hoạt động của interface
};

/* Cấu trúc lưu captured packet cho debugging và monitoring */
struct captured_packet {
    struct list_head list;            // Node trong linked list để quản lý packets
    struct sk_buff *skb;              // Socket buffer chứa packet data thực tế
    char interface_name[IFNAMSIZ];    // Tên interface đã bắt packet này
    unsigned long timestamp;          // Timestamp khi bắt packet (sử dụng jiffies)
    int direction;                    // Hướng packet: 0: vnet0->vnet1, 1: vnet1->vnet0
    __be32 src_ip;                   // Source IP address (network byte order)
    __be32 dst_ip;                   // Destination IP address (network byte order)
    __be16 src_port;                 // Source port (network byte order) 
    __be16 dst_port;                 // Destination port (network byte order)
    __u8 protocol;                   // Protocol type (TCP=6, UDP=17, ICMP=1)
    __u16 packet_size;               // Kích thước thực tế của packet
    bool is_valid;                   // Flag đánh dấu packet có hợp lệ và complete
};

/* Cấu trúc để tracking performance metrics cho monitoring */
struct vnet_performance_stats {
    atomic_t total_packets_forwarded; // Tổng số packets đã forward thành công
    atomic_t total_bytes_forwarded;   // Tổng số bytes đã forward
    atomic_t packets_dropped;         // Số packets bị drop do lỗi hoặc overload
    atomic_t memory_allocation_failures; // Số lần cấp phát memory thất bại
    unsigned long last_reset_time;    // Thời gian reset statistics cuối cùng
};

/* Khai báo biến toàn cục - sẽ được định nghĩa trong source file */
extern struct net_device *vnet_devices[2];  // Mảng chứa 2 network devices
extern struct list_head captured_packets;   // Danh sách packets đã capture
extern spinlock_t capture_lock;              // Lock cho captured packets list
extern int packet_count;                     // Đếm số packets hiện tại
extern struct vnet_performance_stats perf_stats; // Performance statistics

/* Khai báo hàm chính - các hàm network device operations */
int vnet_open(struct net_device *dev);                              // Mở interface
int vnet_close(struct net_device *dev);                             // Đóng interface
netdev_tx_t vnet_start_xmit(struct sk_buff *skb, struct net_device *dev); // Truyền packet
struct net_device_stats *vnet_get_stats(struct net_device *dev);    // Lấy statistics
void vnet_cleanup(void);                                             // Cleanup khi unload

#endif /* VNET_DRIVER_H */
```

## 🚀 Hướng dẫn Build và Install

### Prerequisites
```bash
# Option 1: Sử dụng setup script (Khuyến nghị cho beginners)
chmod +x setup_dev_environment.sh
sudo ./setup_dev_environment.sh

# Option 2: Manual installation (cho advanced users)
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install linux-headers-$(uname -r) build-essential iproute2 netcat-openbsd

# CentOS/RHEL/Fedora  
sudo yum install kernel-devel kernel-headers gcc make iproute2 nc
# hoặc cho Fedora mới
sudo dnf install kernel-devel kernel-headers gcc make iproute2 nc

# Verify kernel headers installation
ls -la /lib/modules/$(uname -r)/build
```

### Build Process với Root Makefile
```bash
# 1. Clone repository
git clone https://github.com/Ndtgithub3333/driver_v2.git
cd driver_v2

# 2. Setup môi trường (nếu chưa làm)
sudo ./setup_dev_environment.sh

# 3. Kiểm tra môi trường có đầy đủ dependencies chưa
make check-env

# 4. Build tất cả modules (sử dụng root Makefile)
make all
# Lệnh này sẽ:
# - Tạo thư mục logs/ (nếu chưa có)  
# - Gọi make -C src để build trong thư mục src/
# - Output: src/vnet_driver.ko và src/vnet_netfilter.ko

# 5. Verify build results (files nằm trong src/)
ls -la src/*.ko
# Expected output:
# src/vnet_driver.ko
# src/vnet_netfilter.ko
```

### Quick Build Options
```bash
# Build từng module riêng (nếu cần)
make driver      # Chỉ build src/vnet_driver.ko
make netfilter   # Chỉ build src/vnet_netfilter.ko

# Debug build với extra flags
make debug       # Build với debug symbols và verbose output
```

### Load Modules và Testing
```bash
# Load modules tự động (build nếu cần)
make load
# Lệnh này sẽ:
# - Check xem src/*.ko có tồn tại chưa
# - Nếu chưa thì tự động build
# - Load vnet_driver.ko trước, sau đó vnet_netfilter.ko

# Verify modules loaded
make status

# Run full test suite (tạo logs/test.log)
make test

# Check test results  
cat logs/test.log
```

## 🧪 Testing và Verification

### 1. Automatic Testing (Khuyến nghị)
```bash
# Full test suite với root Makefile
make test
# Test này sẽ:
# - Tự động build modules (nếu cần)
# - Load modules vào kernel
# - Tạo và configure vnet0, vnet1 interfaces  
# - Test packet forwarding functionality
# - Test netfilter packet capture
# - Tạo logs/test.log với kết quả chi tiết

# Monitor test progress realtime
tail -f logs/test.log

# Quick test (với test_driver.sh trực tiếp)  
sudo ./test_driver.sh
```

### 2. Manual Testing Step by Step
```bash
# 1. Load modules manually
make load
# hoặc
sudo insmod src/vnet_driver.ko
sudo insmod src/vnet_netfilter.ko

# 2. Verify interfaces created
ip link show | grep vnet
# Expected output:
# vnet0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default
# vnet1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default

# 3. Configure interfaces  
sudo ip addr add 192.168.100.1/24 dev vnet0
sudo ip addr add 192.168.100.2/24 dev vnet1
sudo ip link set vnet0 up
sudo ip link set vnet1 up

# 4. Verify configuration
ip addr show vnet0
ip addr show vnet1

# 5. Check modules loaded properly
lsmod | grep vnet
# Expected output:
# vnet_netfilter         16384  0
# vnet_driver            20480  0
```

### 3. Packet Transfer Testing
```bash
# Test với netcat (khuyến nghị)
# Terminal 1: Start server trên vnet1
nc -l -s 192.168.100.2 -p 8080

# Terminal 2: Connect từ vnet0
echo "Hello from vnet0 to vnet1" | nc -s 192.168.100.1 192.168.100.2 8080

# Test với ping (có thể không work với virtual interfaces)
ping -c 3 -I vnet0 192.168.100.2

# Test UDP traffic
# Terminal 1: UDP server
nc -u -l -s 192.168.100.2 -p 9090

# Terminal 2: Send UDP data
echo "UDP test data" | nc -u -s 192.168.100.1 192.168.100.2 9090
```

### 4. Monitoring và Debug
```bash
# 1. Overall status check
make status
# Output bao gồm:
# - Loaded modules status
# - Network interfaces status  
# - Proc files availability

# 2. Kernel logs liên quan vnet
make show-logs
# hoặc
dmesg | grep -E 'vnet|netfilter' | tail -20

# 3. Packet capture statistics (nếu có)
make capture
# hoặc  
cat /proc/vnet_capture 2>/dev/null

# 4. Network statistics monitoring
cat /proc/net/dev | grep vnet
# hoặc real-time monitoring
watch -n 1 'cat /proc/net/dev | grep vnet'

# 5. Interface details với ip command
ip -s link show vnet0  # Statistics cho vnet0
ip -s link show vnet1  # Statistics cho vnet1
```

## 📊 Performance Monitoring

### Built-in Statistics Tracking
```c
// Driver tự động track các metrics trong kernel space:
struct vnet_priv {
    struct net_device_stats stats;  // Standard network statistics
    // stats.tx_packets;            // Số packets đã transmit
    // stats.rx_packets;            // Số packets đã receive  
    // stats.tx_bytes;              // Số bytes đã transmit
    // stats.rx_bytes;              // Số bytes đã receive
    // stats.tx_dropped;            // Số packets bị drop khi transmit
    // stats.rx_dropped;            // Số packets bị drop khi receive
    unsigned long last_tx_jiffies;  // Timestamp transmission cuối cùng
    unsigned long last_rx_jiffies;  // Timestamp receive cuối cùng
};

// Global atomic counters cho thread-safe tracking
atomic_t total_packets_sent;     // Tổng packets đã gửi (across all interfaces)
atomic_t total_packets_received; // Tổng packets đã nhận (across all interfaces)
```

### Monitoring Commands
```bash
# 1. Comprehensive status với root Makefile
make status

# 2. Standard network interface statistics
cat /proc/net/dev | grep vnet
# Output format:
# vnet0: bytes packets errs drop fifo frame compressed multicast
# vnet1: bytes packets errs drop fifo frame compressed multicast

# 3. Detailed per-interface statistics với ip command
ip -s link show vnet0
ip -s link show vnet1

# 4. Real-time monitoring
watch -n 1 'cat /proc/net/dev | grep vnet'

# 5. Kernel log analysis cho performance data
dmesg | grep -E 'vnet.*packets|vnet.*bytes|vnet.*performance'
```

## 🔍 Troubleshooting

### Common Issues và Solutions

#### 1. Build Environment Issues
```bash
# Lỗi: "No such file or directory: /lib/modules/$(uname -r)/build"
# Debug:
make check-env
ls -la /lib/modules/$(uname -r)/

# Giải pháp:
sudo apt-get install linux-headers-$(uname -r)  # Ubuntu/Debian
sudo yum install kernel-devel kernel-headers    # CentOS/RHEL
sudo dnf install kernel-devel kernel-headers    # Fedora

# Verify fix:
ls -la /lib/modules/$(uname -r)/build && echo "Headers OK"
```

#### 2. Build Compilation Issues
```bash
# Lỗi: Build failed with compilation errors
# Debug:
cat logs/test.log    # Check test logs nếu có
cd src && make clean && make V=1  # Verbose build output

# Common fixes:
make clean           # Clean all build artifacts
make check-env       # Verify environment
sudo ./setup_dev_environment.sh  # Reinstall dependencies

# Advanced debugging:
cd src
make clean
EXTRA_CFLAGS="-Wall -Wextra" make  # Build với extra warnings
```

#### 3. Module Loading Issues
```bash
# Lỗi: "Operation not permitted" hoặc "Invalid module format"
# Debug:
file src/vnet_driver.ko     # Check file format
modinfo src/vnet_driver.ko  # Verify module info
dmesg | tail -10            # Check kernel messages

# Giải pháp:
make unload                 # Unload any old versions
make clean && make all      # Clean rebuild
make load                   # Load fresh modules

# Check kernel taint:
cat /proc/sys/kernel/tainted  # Should be 0 for clean kernel
```

#### 4. Interface Creation Issues
```bash
# Lỗi: vnet0, vnet1 interfaces không xuất hiện
# Debug:
make status                    # Check overall status
lsmod | grep vnet             # Verify modules loaded
dmesg | grep "register_netdev" # Check device registration

# Giải pháp:
make reload                   # Unload và reload modules
dmesg | grep vnet | tail -10  # Check for error messages

# Manual debugging:
sudo rmmod vnet_netfilter vnet_driver
sudo insmod src/vnet_driver.ko
# Check dmesg immediately after load
dmesg | tail -5
```

#### 5. Packet Forwarding Issues
```bash
# Lỗi: Packets không forward giữa vnet0 và vnet1
# Debug:
tcpdump -i vnet0 -v          # Monitor vnet0 traffic
tcpdump -i vnet1 -v          # Monitor vnet1 traffic (in another terminal)
make show-logs | grep "xmit" # Check transmission logs

# Verify setup:
ip addr show vnet0           # Check IP configuration
ip addr show vnet1
ip link show vnet0 | grep UP # Ensure interfaces are UP
ip link show vnet1 | grep UP

# Test basic connectivity:
sudo ip link set vnet0 up
sudo ip link set vnet1 up
ip route | grep vnet         # Check routing table
```

#### 6. Permission và Access Issues
```bash
# Lỗi: "Permission denied" cho network operations
# Giải pháp:
sudo su                      # Switch to root for testing
# hoặc
sudo usermod -a -G netdev $USER  # Add user to netdev group
newgrp netdev               # Activate group membership

# For persistent solution:
sudo ./setup_dev_environment.sh  # Setup proper permissions
```

### Debug Utilities và Helpers
```bash
# 1. Development aliases (sau khi chạy setup script)
vnet-build      # Quick build shortcut
vnet-test       # Quick test shortcut  
vnet-debug      # Debug information display
vnet-status     # Overall status check
vnet-logs       # View kernel logs
vnet-clean      # Clean build artifacts

# 2. Manual debug commands
dmesg -c                     # Clear và show kernel messages
echo 7 > /proc/sys/kernel/printk  # Enable all kernel debug messages
dmesg -w | grep vnet         # Real-time kernel log monitoring

# 3. Network debugging
ss -tuln | grep :808        # Check listening sockets
netstat -i | grep vnet      # Interface statistics
ethtool vnet0               # Interface details (if supported)
```

## 🧹 Cleanup và Uninstall

### Quick Cleanup với Makefile
```bash
# Complete cleanup với single command
make unload     # Unload modules
make clean      # Clean build files và logs

# Verify cleanup success
make status     # Should show no modules loaded
ls src/*.ko     # Should not find any .ko files
ls logs/        # Should be empty or non-existent
```

### Manual Step-by-Step Cleanup
```bash
# 1. Stop tất cả test processes
pkill -f "nc.*vnet" || true

# 2. Down interfaces trước khi unload modules
sudo ip link set vnet0 down 2>/dev/null || true
sudo ip link set vnet1 down 2>/dev/null || true

# 3. Remove IP addresses
sudo ip addr flush dev vnet0 2>/dev/null || true
sudo ip addr flush dev vnet1 2>/dev/null || true

# 4. Unload modules (thứ tự quan trọng: netfilter trước, driver sau)
sudo rmmod vnet_netfilter 2>/dev/null || true
sudo rmmod vnet_driver 2>/dev/null || true

# 5. Clean build artifacts
cd src && make clean

# 6. Remove logs
rm -rf logs/

# 7. Verify complete cleanup
lsmod | grep vnet            # Should return empty
ip link show | grep vnet     # Should return empty  
ls src/*.ko 2>/dev/null      # Should not find files
```

### Comprehensive System Cleanup
```bash
# For development environment reset
sudo ./setup_dev_environment.sh --uninstall  # Nếu script hỗ trợ
# hoặc manual cleanup:

# Remove aliases nếu đã tạo
rm -f ~/.bashrc.d/vnet-aliases.sh
# Remove development scripts  
sudo rm -f /usr/local/bin/vnet-*

# Reset kernel parameters nếu đã thay đổi
sudo rm -f /etc/sysctl.d/99-vnet-driver.conf
sudo sysctl --system
```

## 📈 Advanced Features

### 1. Comprehensive Logging System
```bash
# Log structure thực tế:
logs/
└── test.log           # Chỉ có file này được tạo khi chạy make test

# Log content bao gồm:
# - Module compilation status
# - Module loading results  
# - Interface creation logs
# - Network configuration logs
# - Connectivity test results
# - Packet capture verification
# - Performance test data
# - Error messages và debugging info
```

### 2. Development Environment Features
```bash
# Aliases được tạo bởi setup script:
alias vnet-build='cd /path/to/driver_v2 && make all'
alias vnet-test='cd /path/to/driver_v2 && make test'  
alias vnet-debug='dmesg | grep -E "vnet|netfilter" | tail -20'
alias vnet-status='cd /path/to/driver_v2 && make status'
alias vnet-logs='dmesg | grep -E "vnet|netfilter_capture" | tail -20'
alias vnet-capture='cat /proc/vnet_capture 2>/dev/null || echo "Capture not available"'
alias vnet-clean='cd /path/to/driver_v2 && make clean'

# Utility scripts:
/usr/local/bin/vnet-debug   # Comprehensive debug information script
```

### 3. Build System Features
```makefile
# Root Makefile targets thực tế:
help                 # Hiển thị menu help với descriptions
all                  # Build tất cả modules (output trong src/)
driver               # Build chỉ vnet_driver.ko  
netfilter            # Build chỉ vnet_netfilter.ko
test                 # Chạy full test suite (tạo logs/test.log)
test-quick           # Quick test (timeout 300s)
load                 # Load modules từ src/*.ko
unload               # Unload modules
reload               # Unload + load
clean                # Clean src/ và logs/
check-env            # Verify development environment
status               # Hiển thị modules và interfaces status
show-logs            # Show kernel logs liên quan vnet
capture              # Show packet capture stats
debug                # Debug build với extra flags
```

### 4. Cross-platform Support Details
- **Ubuntu/Debian**: Auto-install với `apt-get` (linux-headers, build-essential, netcat-openbsd)
- **CentOS/RHEL**: Auto-install với `yum` (kernel-devel, kernel-headers, nc)  
- **Fedora**: Auto-install với `dnf` (kernel-devel, kernel-headers, nc)
- **Generic Linux**: Fallback instructions cho manual installation

## 🎓 Educational Value

### Learning Outcomes
1. **Linux Kernel Programming**
   - Module development lifecycle (init, cleanup, error handling)
   - Device drivers architecture và best practices
   - Kernel space vs user space communication
   - Memory management trong kernel (kmalloc, kfree, GFP flags)

2. **Network Stack Deep Dive**
   - Network device operations (ndo_open, ndo_stop, ndo_start_xmit)
   - SKB (socket buffer) manipulation và lifecycle
   - Packet flow trong Linux kernel network stack
   - Interface registration và management

3. **Netfilter Framework Mastery**
   - Hook registration và callback implementation
   - Packet inspection techniques (IP, TCP, UDP headers)
   - Network monitoring without disrupting packet flow
   - Integration với kernel networking subsystem

4. **System Programming Excellence**  
   - Concurrency control với spinlocks và atomic operations
   - Error handling strategies trong kernel space
   - Resource management (proper cleanup paths)
   - Thread-safe programming patterns

5. **DevOps và Build Systems**
   - Makefile design cho kernel module projects
   - Automated testing strategies  
   - Cross-platform development practices
   - Documentation và project organization

### Code Quality Features
- **Extensive logging**: Debug, info, warning, error levels với kernel printk
- **Thread safety**: Spinlocks cho critical sections, atomic counters
- **Memory safety**: Proper SKB handling, no memory leaks
- **Error handling**: Graceful degradation, proper cleanup paths
- **Documentation**: Comprehensive comments trong code (Vietnamese + English)
- **Testing**: Automated test suite với real packet forwarding verification

## 📚 References và Learning Resources

### Essential Documentation
- [Linux Kernel Networking](https://www.kernel.org/doc/Documentation/networking/)
- [Network Device Drivers](https://lwn.net/Kernel/LDD3/ch17.lwn)
- [Netfilter Framework Documentation](https://netfilter.org/documentation/)
- [Linux Device Drivers Book](https://lwn.net/Kernel/LDD3/) - Chapter 17

### Recommended Books
- "Linux Device Drivers" by Jonathan Corbet, Alessandro Rubini, Greg Kroah-Hartman
- "Understanding Linux Network Internals" by Christian Benvenuti  
- "Linux Kernel Development" by Robert Love
- "Professional Linux Kernel Architecture" by Wolfgang Mauerer

### Online Resources
- [Kernel Newbies](https://kernelnewbies.org/) - Beginner-friendly kernel development
- [Linux Cross Reference](https://elixir.bootlin.com/linux/latest/source) - Browse kernel source
- [NetDev Conference](https://www.netdevconf.org/) - Network development videos
- [Linux Kernel Mailing List](https://lkml.org/) - Official kernel development discussions

### Sample Code References
- [Linux Kernel Examples](https://github.com/torvalds/linux/tree/master/drivers/net)
- [Network Driver Tutorial](https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html)

## 🤝 Contributing

### Development Workflow
```bash
# 1. Fork repository trên GitHub  
# 2. Clone your fork
git clone https://github.com/yourusername/driver_v2.git
cd driver_v2

# 3. Setup development environment
sudo ./setup_dev_environment.sh

# 4. Create feature branch
git checkout -b feature/your-feature-name

# 5. Develop và test thoroughly
make clean
make all
make test           # Full test suite
make test-quick     # Quick verification

# 6. Verify code quality
# - Check for compilation warnings
# - Test trên multiple kernel versions nếu possible
# - Ensure no memory leaks
# - Test error handling paths

# 7. Commit với descriptive messages
git add .
git commit -m "Add: feature description with technical details"

# 8. Push và create Pull Request
git push origin feature/your-feature-name
```

### Code Style Guidelines
- **Follow Linux kernel coding style** (Documentation/process/coding-style.rst)
- **Add comprehensive comments** (Vietnamese acceptable cho educational purposes)
- **Include error handling** cho all functions và edge cases
- **Test thoroughly** với both unit và integration testing
- **Update documentation** khi có changes trong functionality

### Testing Requirements cho Contributors
```bash
# Before submitting PR, verify:
make clean              # Clean build từ scratch
make all               # Successful compilation
make test              # Full test suite passes
make test-quick        # Quick functionality verification  

# Check logs cho warnings/errors:
grep -E 'ERROR|WARNING|error|warning' logs/test.log

# Test trên different scenarios:
# - Clean kernel (no modules loaded)
# - Multiple load/unload cycles  
# - Stress test với high packet volume
# - Error injection testing
```

## 📄 License

```
GPL v2 License

This kernel module is developed for educational and research purposes.
The code is distributed under GPL v2 license compatible with Linux kernel.
See COPYING or LICENSE file for full license details.

Disclaimer: 
This module is intended for testing and learning environments only.
Do not use in production environments without proper security review
and testing. The authors are not responsible for any damage or
security issues arising from the use of this code.

Educational Purpose:
This project is designed to teach Linux kernel programming concepts,
network device driver development, and netfilter framework usage.
```

## 👨‍💻 Author & Project Information

**Developer**: Ndtgithub3333  
**Project**: Linux Virtual Network Driver v2.0  
**Repository**: https://github.com/Ndtgithub3333/driver_v2  
**Status**: Active Development (Educational Project)  
**Kernel Compatibility**: Linux 4.x, 5.x, 6.x  
**Architecture**: x86_64 (primary), ARM64 (untested)  

---

## 🏃‍♂️ Quick Start Guide

### Dành cho người mới bắt đầu:

```bash
# 1. Download project
git clone https://github.com/Ndtgithub3333/driver_v2.git
cd driver_v2

# 2. One-command setup (setup môi trường tự động)
sudo ./setup_dev_environment.sh

# 3. Build và test với single command
make test
# Command này sẽ:
# - Build modules trong src/
# - Load modules vào kernel
# - Configure network interfaces
# - Test packet forwarding  
# - Tạo logs/test.log với kết quả

# 4. Monitor results
tail -f logs/test.log      # Real-time test progress
make status                # Overall status check

# 5. Cleanup sau khi test
make unload && make clean
```

### Dành cho developers có kinh nghiệm:

```bash
# 1. Quick environment verification
make check-env

# 2. Selective builds
make driver               # Build chỉ main driver (src/vnet_driver.ko)
make netfilter            # Build chỉ netfilter module (src/vnet_netfilter.ko)
make debug                # Debug build với extra symbols

# 3. Manual testing cycle
make load                 # Load modules from src/
ip link show | grep vnet  # Verify interfaces
make capture              # Monitor packet capture
make unload               # Clean unload

# 4. Development cycle optimization
make reload               # Quick unload + load
make clean && make all    # Full rebuild
```

**Lưu ý quan trọng**: 
- **Build output location**: Tất cả `.ko` files được tạo trong `src/` directory, không phải `build/`
- **Log files**: Chỉ có `logs/test.log` được tạo khi chạy `make test`
- **Root privileges**: Kernel module operations luôn cần sudo/root
- **Testing**: Sử dụng `make status` để check overall health của system

---

*README này cung cấp hướng dẫn chính xác và chi tiết về cấu trúc thực tế của project. Bắt đầu với Quick Start Guide, sau đó tham khảo các sections specific theo nhu cầu development của bạn.*
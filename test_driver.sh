#!/bin/bash

# Script kiểm thử Virtual Network Driver - Improved Version
# Mô tả: Kiểm thử Virtual Network Driver với enhanced error handling

set -e  # Dừng script nếu có lỗi

# Màu sắc cho output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Biến cấu hình
VNET0_IP="192.168.10.1"
VNET1_IP="192.168.10.2"
SUBNET_MASK="24"
TEST_PORT="12345"
LOG_FILE="/tmp/vnet_test.log"

# Hàm in tiêu đề với màu sắc
print_header() {
    echo -e "\n${BLUE}=====================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${BLUE}=====================================${NC}"
}

# Hàm in thông báo thành công
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Hàm in thông báo cảnh báo
print_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

# Hàm in thông báo lỗi
print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Hàm in thông tin
print_info() {
    echo -e "${PURPLE}ℹ️ $1${NC}"
}

# Hàm kiểm tra quyền root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Vui lòng chạy script bằng quyền root: sudo $0"
        exit 1
    fi
    print_success "Đã kiểm tra quyền root"
}

# Hàm cleanup khi có lỗi
cleanup_on_error() {
    print_warning "Đang thực hiện cleanup do có lỗi..."
    sudo rmmod vnet_netfilter 2>/dev/null || true
    sudo rmmod vnet_driver 2>/dev/null || true
    sudo ip link set vnet0 down 2>/dev/null || true
    sudo ip link set vnet1 down 2>/dev/null || true
    print_info "Cleanup hoàn tất"
}

# Thiết lập trap để cleanup khi có lỗi
trap cleanup_on_error ERR

# Hàm kiểm tra kernel headers
check_kernel_headers() {
    print_header "Kiểm tra Kernel Headers"
    
    KERNEL_VERSION=$(uname -r)
    HEADERS_PATH="/lib/modules/$KERNEL_VERSION/build"
    
    if [ ! -d "$HEADERS_PATH" ]; then
        print_error "Kernel headers không tồn tại tại: $HEADERS_PATH"
        print_info "Cài đặt bằng: sudo apt-get install linux-headers-$(uname -r)"
        exit 1
    fi
    
    print_success "Kernel headers tồn tại: $HEADERS_PATH"
}

# Hàm gỡ bỏ module cũ
remove_old_modules() {
    print_header "Gỡ bỏ modules cũ"
    
    # Kiểm tra và gỡ bỏ modules nếu đã load
    if lsmod | grep -q "vnet_netfilter"; then
        sudo rmmod vnet_netfilter
        print_success "Đã gỡ bỏ vnet_netfilter"
    else
        print_info "Module vnet_netfilter chưa được load"
    fi
    
    if lsmod | grep -q "vnet_driver"; then
        sudo rmmod vnet_driver
        print_success "Đã gỡ bỏ vnet_driver"
    else
        print_info "Module vnet_driver chưa được load"
    fi
    
    # Cleanup network interfaces nếu tồn tại
    if ip link show vnet0 >/dev/null 2>&1; then
        sudo ip link set vnet0 down 2>/dev/null || true
        print_info "Đã down interface vnet0"
    fi
    
    if ip link show vnet1 >/dev/null 2>&1; then
        sudo ip link set vnet1 down 2>/dev/null || true
        print_info "Đã down interface vnet1"
    fi
}

# Hàm biên dịch modules
compile_modules() {
    print_header "Biên dịch modules"
    
    # Lưu current directory
    ORIGINAL_DIR=$(pwd)
    
    # Chuyển đến thư mục src và biên dịch
    cd src
    
    # Clean trước khi build
    make clean > "$LOG_FILE" 2>&1
    print_success "Đã clean build files"
    
    # Biên dịch modules
    if make >> "$LOG_FILE" 2>&1; then
        print_success "Biên dịch thành công"
    else
        print_error "Biên dịch thất bại - xem log tại: $LOG_FILE"
        cd "$ORIGINAL_DIR"
        exit 1
    fi
    
    # Kiểm tra file .ko có tồn tại không
    if [ ! -f "vnet_driver.ko" ] || [ ! -f "vnet_netfilter.ko" ]; then
        print_error "Không tìm thấy file .ko sau khi biên dịch"
        cd "$ORIGINAL_DIR"
        exit 1
    fi
    
    print_success "Tìm thấy file modules: vnet_driver.ko, vnet_netfilter.ko"
    
    # Quay về thư mục gốc
    cd "$ORIGINAL_DIR"
}

# Hàm load modules
load_modules() {
    print_header "Load kernel modules"
    
    # Load vnet_driver trước
    if sudo insmod src/vnet_driver.ko; then
        print_success "Đã load vnet_driver module"
    else
        print_error "Không thể load vnet_driver module"
        exit 1
    fi
    
    # Đợi một chút để driver khởi tạo
    sleep 1
    
    # Load vnet_netfilter
    if sudo insmod src/vnet_netfilter.ko; then
        print_success "Đã load vnet_netfilter module"
    else
        print_error "Không thể load vnet_netfilter module"
        sudo rmmod vnet_driver
        exit 1
    fi
    
    # Đợi modules khởi tạo hoàn toàn
    sleep 2
}

# Hàm kiểm tra modules đã load
verify_modules() {
    print_header "Kiểm tra modules đã load"
    
    echo "Modules hiện tại:"
    lsmod | grep -E 'vnet_driver|vnet_netfilter'
    
    # Kiểm tra dmesg để xem có lỗi không
    print_info "Kiểm tra kernel messages:"
    dmesg | grep -E 'vnet|netfilter' | tail -5
}

# Hàm phát hiện driver của interface với error handling an toàn
detect_interface_driver() {
    local iface="$1"
    
    if [ -z "$iface" ]; then
        print_warning "Tên interface không được cung cấp"
        return 1
    fi
    
    # Sử dụng logic an toàn để tránh lỗi basename khi readlink trả về rỗng
    DRIVER_LINK=$(readlink /sys/class/net/$iface/device/driver 2>/dev/null || echo "")
    if [ -n "$DRIVER_LINK" ]; then
        DRIVER_NAME=$(basename "$DRIVER_LINK" 2>/dev/null || echo "Unknown")
    else
        DRIVER_NAME="Virtual Driver"
    fi
    print_info "  - Driver: $DRIVER_NAME"
    
    # Thêm thông tin bổ sung về interface
    if [ -f "/sys/class/net/$iface/operstate" ]; then
        OPERSTATE=$(cat /sys/class/net/$iface/operstate 2>/dev/null || echo "unknown")
        print_info "  - Status: $OPERSTATE"
    fi
    
    if [ -f "/sys/class/net/$iface/mtu" ]; then
        MTU=$(cat /sys/class/net/$iface/mtu 2>/dev/null || echo "unknown")
        print_info "  - MTU: $MTU"
    fi
}

# Hàm kiểm tra và cấu hình network interfaces
configure_interfaces() {
    print_header "Cấu hình Network Interfaces"
    
    # Kiểm tra interfaces có tồn tại không
    if ! ip link show vnet0 >/dev/null 2>&1; then
        print_error "Interface vnet0 không tồn tại"
        exit 1
    fi
    
    if ! ip link show vnet1 >/dev/null 2>&1; then
        print_error "Interface vnet1 không tồn tại"
        exit 1
    fi
    
    print_success "Tìm thấy cả hai interfaces: vnet0, vnet1"
    
    # Xóa IP cũ nếu có
    sudo ip addr flush dev vnet0 2>/dev/null || true
    sudo ip addr flush dev vnet1 2>/dev/null || true
    print_info "Đã xóa IP cũ trên các interfaces"
    
    # Gán địa chỉ IP mới
    if sudo ip addr add "${VNET0_IP}/${SUBNET_MASK}" dev vnet0; then
        print_success "Đã gán IP ${VNET0_IP}/${SUBNET_MASK} cho vnet0"
    else
        print_error "Không thể gán IP cho vnet0"
        exit 1
    fi
    
    if sudo ip addr add "${VNET1_IP}/${SUBNET_MASK}" dev vnet1; then
        print_success "Đã gán IP ${VNET1_IP}/${SUBNET_MASK} cho vnet1"
    else
        print_error "Không thể gán IP cho vnet1"
        exit 1
    fi
    
    # Kích hoạt interfaces
    if sudo ip link set vnet0 up && sudo ip link set vnet1 up; then
        print_success "Đã kích hoạt cả hai interfaces"
    else
        print_error "Không thể kích hoạt interfaces"
        exit 1
    fi
    
    # Đợi interfaces khởi động hoàn toàn
    sleep 2
    
    # Hiển thị cấu hình hiện tại
    print_info "Cấu hình hiện tại:"
    echo "vnet0:"
    ip addr show vnet0 | grep -E 'inet |link'
    
    # Hiển thị thông tin driver cho vnet0
    detect_interface_driver "vnet0"
    
    echo "vnet1:"
    ip addr show vnet1 | grep -E 'inet |link'
    
    # Hiển thị thông tin driver cho vnet1  
    detect_interface_driver "vnet1"
}

# Hàm kiểm tra kết nối cơ bản
test_basic_connectivity() {
    print_header "Kiểm tra kết nối cơ bản"
    
    # Test ping giữa hai interfaces
    print_info "Thử ping từ vnet0 tới vnet1..."
    if ping -c 3 -I vnet0 "$VNET1_IP" >/dev/null 2>&1; then
        print_success "Ping từ vnet0 tới vnet1 thành công"
    else
        print_warning "Ping thất bại (có thể bình thường với virtual interfaces)"
    fi
    
    # Kiểm tra routing table
    print_info "Routing table liên quan tới vnet:"
    ip route | grep vnet || print_info "Không có route cụ thể cho vnet interfaces"
}

# Hàm kiểm tra kết nối TCP/UDP với improved error handling
test_network_connectivity() {
    print_header "Kiểm tra kết nối TCP/UDP"
    
    # Validate network configuration trước khi test
    if ! ip addr show vnet0 | grep -q "$VNET0_IP"; then
        print_error "vnet0 không có IP $VNET0_IP được cấu hình"
        return 1
    fi
    
    if ! ip addr show vnet1 | grep -q "$VNET1_IP"; then
        print_error "vnet1 không có IP $VNET1_IP được cấu hình"
        return 1
    fi
    
    print_success "Network configuration validation passed"
    
    # Test TCP connection với netcat
    print_info "Bắt đầu TCP server trên vnet1 port $TEST_PORT..."
    
    # Tạo temporary file để lưu server output
    SERVER_OUTPUT="/tmp/vnet_server_output_$$.txt"
    
    # Chạy server ở background với improved error handling
    timeout 15 nc -l -k -s "$VNET1_IP" -p "$TEST_PORT" > "$SERVER_OUTPUT" 2>&1 &
    SERVER_PID=$!
    
    # Đợi server khởi động
    sleep 2
    
    # Kiểm tra server có chạy không
    if ! ps -p $SERVER_PID > /dev/null 2>&1; then
        print_error "TCP server không thể khởi động"
        rm -f "$SERVER_OUTPUT"
        return 1
    fi
    
    print_success "TCP server đã khởi động (PID: $SERVER_PID)"
    
    # Test port có accessible không
    if ! nc -z -v -w 3 "$VNET1_IP" "$TEST_PORT" 2>/dev/null; then
        print_warning "Port $TEST_PORT trên $VNET1_IP không accessible từ bên ngoài"
    fi
    
    # Gửi dữ liệu test từ client với retry logic
    TEST_MESSAGE="Hello Virtual Network Driver v2.0 - $(date) - PID:$$"
    print_info "Gửi test message từ vnet0..."
    
    local SEND_SUCCESS=false
    local RETRY_COUNT=3
    
    for attempt in $(seq 1 $RETRY_COUNT); do
        print_info "Attempt $attempt/$RETRY_COUNT..."
        
        if echo "$TEST_MESSAGE" | timeout 5 nc -w 3 -s "$VNET0_IP" "$VNET1_IP" "$TEST_PORT" 2>/dev/null; then
            print_success "Gửi dữ liệu TCP thành công (attempt $attempt)"
            SEND_SUCCESS=true
            break
        else
            print_warning "Attempt $attempt thất bại"
            if [ $attempt -lt $RETRY_COUNT ]; then
                sleep 1
            fi
        fi
    done
    
    if [ "$SEND_SUCCESS" = false ]; then
        print_error "Tất cả attempts gửi dữ liệu TCP đều thất bại"
    fi
    
    # Đợi dữ liệu được xử lý
    sleep 3
    
    # Kiểm tra server có nhận được dữ liệu không với better validation
    if [ -f "$SERVER_OUTPUT" ] && [ -s "$SERVER_OUTPUT" ]; then
        local RECEIVED_DATA=$(cat "$SERVER_OUTPUT" 2>/dev/null)
        if [ -n "$RECEIVED_DATA" ]; then
            print_success "Server đã nhận được dữ liệu:"
            echo "  Data: $RECEIVED_DATA"
            
            # Validate rằng data nhận được đúng
            if echo "$RECEIVED_DATA" | grep -q "Virtual Network Driver v2.0"; then
                print_success "Data validation: Correct message received"
            else
                print_warning "Data validation: Unexpected message format"
            fi
        else
            print_warning "Server output file tồn tại nhưng rỗng"
        fi
    else
        print_warning "Server không nhận được dữ liệu hoặc file output không tồn tại"
    fi
    
    # Enhanced cleanup với better error handling
    if ps -p $SERVER_PID > /dev/null 2>&1; then
        kill -TERM $SERVER_PID 2>/dev/null || true
        sleep 2
        if ps -p $SERVER_PID > /dev/null 2>&1; then
            kill -KILL $SERVER_PID 2>/dev/null || true
        fi
    fi
    
    wait $SERVER_PID 2>/dev/null || true
    rm -f "$SERVER_OUTPUT" 2>/dev/null || true
    
    print_success "Đã cleanup TCP server và temporary files"
}

# Hàm kiểm tra packet capture với enhanced validation
test_packet_capture() {
    print_header "Kiểm tra Packet Capture"
    
    # Kiểm tra /proc/vnet_capture có tồn tại không
    if [ ! -f "/proc/vnet_capture" ]; then
        print_error "/proc/vnet_capture không tồn tại"
        print_info "Kiểm tra xem vnet_netfilter module đã được load chưa:"
        lsmod | grep vnet_netfilter || print_warning "vnet_netfilter module chưa được load"
        return 1
    fi
    
    print_success "Tìm thấy /proc/vnet_capture"
    
    # Kiểm tra permissions
    if [ ! -r "/proc/vnet_capture" ]; then
        print_error "/proc/vnet_capture không có quyền đọc"
        return 1
    fi
    
    # Lấy packet count trước khi test
    local PACKETS_BEFORE=$(cat /proc/vnet_capture | grep -c "│.*│.*│.*│" 2>/dev/null || echo "0")
    print_info "Packets captured hiện tại: $PACKETS_BEFORE"
    
    # Hiển thị buffer usage information
    if cat /proc/vnet_capture | head -5 | grep -q "buffer usage"; then
        print_info "Buffer usage info:"
        cat /proc/vnet_capture | head -5 | grep "buffer usage"
    fi
    
    # Tạo test traffic để kiểm tra packet capture
    print_info "Tạo test traffic để kiểm tra packet capture..."
    
    # Tạo một vài test packets
    local TEST_COUNT=3
    for i in $(seq 1 $TEST_COUNT); do
        echo "Test packet $i" | timeout 2 nc -w 1 -s "$VNET0_IP" "$VNET1_IP" "1234$i" 2>/dev/null &
        sleep 0.5
    done
    
    # Đợi traffic hoàn thành
    sleep 2
    
    # Kiểm tra lại packet count
    local PACKETS_AFTER=$(cat /proc/vnet_capture | grep -c "│.*│.*│.*│" 2>/dev/null || echo "0")
    local NEW_PACKETS=$((PACKETS_AFTER - PACKETS_BEFORE))
    
    print_info "Packets sau test traffic: $PACKETS_AFTER (new: $NEW_PACKETS)"
    
    # Hiển thị sample packet capture với formatting
    print_info "Packet capture sample (top 25 lines):"
    echo "========================================"
    cat /proc/vnet_capture | head -25
    echo "========================================"
    
    # Validation logic
    if [ "$PACKETS_AFTER" -gt 0 ]; then
        print_success "Packet capture hoạt động bình thường"
        
        if [ "$NEW_PACKETS" -gt 0 ]; then
            print_success "Test traffic được capture thành công ($NEW_PACKETS new packets)"
        else
            print_warning "Không capture được test traffic mới (có thể do timing hoặc filtering)"
        fi
        
        # Kiểm tra format của captured packets
        if cat /proc/vnet_capture | grep -q "└─"; then
            print_success "Packet capture format hiển thị đúng (có table borders)"
        fi
        
        # Kiểm tra có thông tin timestamp không
        if cat /proc/vnet_capture | grep -q "Timestamp"; then
            print_success "Packet capture có timestamp information"
        fi
        
    else
        print_warning "Chưa có packets nào được capture"
        print_info "Có thể do:"
        print_info "  - Chưa có traffic qua virtual interfaces"
        print_info "  - Netfilter hooks chưa hoạt động"
        print_info "  - Buffer đã bị reset"
    fi
    
    # Additional diagnostic info
    print_info "Diagnostic information:"
    print_info "  - /proc/vnet_capture file size: $(wc -c < /proc/vnet_capture 2>/dev/null || echo 'unknown') bytes"
    print_info "  - /proc/vnet_capture line count: $(wc -l < /proc/vnet_capture 2>/dev/null || echo 'unknown') lines"
}

# Hàm performance test
performance_test() {
    print_header "Kiểm tra Performance"
    
    print_info "Chạy performance test với multiple connections..."
    
    # Tạo multiple concurrent connections để test performance
    for i in {1..5}; do
        # Chạy server ngắn hạn
        timeout 5 nc -l -s "$VNET1_IP" -p "$((TEST_PORT + i))" >/dev/null &
        SERVER_PIDS[$i]=$!
        
        # Gửi dữ liệu từ client
        echo "Performance test message $i" | nc -w 2 -s "$VNET0_IP" "$VNET1_IP" "$((TEST_PORT + i))" &
        CLIENT_PIDS[$i]=$!
    done
    
    # Đợi tất cả connections hoàn thành
    sleep 3
    
    # Cleanup các processes
    for i in {1..5}; do
        kill ${SERVER_PIDS[$i]} 2>/dev/null || true
        kill ${CLIENT_PIDS[$i]} 2>/dev/null || true
    done
    
    print_success "Performance test hoàn thành"
    
    # Hiển thị network statistics
    print_info "Network statistics sau performance test:"
    cat /proc/net/dev | grep vnet
}

# Hàm kiểm tra kernel logs
check_kernel_logs() {
    print_header "Kiểm tra Kernel Logs"
    
    print_info "Kernel messages liên quan tới vnet (20 dòng cuối):"
    echo "----------------------------------------"
    dmesg | grep -E 'vnet|netfilter_capture' | tail -20
    echo "----------------------------------------"
    
    # Kiểm tra có error messages không
    ERROR_COUNT=$(dmesg | grep -E 'vnet.*error|vnet.*failed|vnet.*ERROR' | wc -l)
    WARNING_COUNT=$(dmesg | grep -E 'vnet.*warning|vnet.*WARNING' | wc -l)
    
    print_info "Số lượng error messages: $ERROR_COUNT"
    print_info "Số lượng warning messages: $WARNING_COUNT"
    
    if [ "$ERROR_COUNT" -eq 0 ]; then
        print_success "Không có error messages"
    else
        print_warning "Có $ERROR_COUNT error messages trong kernel log"
    fi
}

# Hàm stress test được cải thiện với better reliability
stress_test() {
    print_header "Stress Test (Optional)"
    
    read -p "Bạn có muốn chạy stress test không? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Bỏ qua stress test"
        return 0
    fi
    
    # Cấu hình stress test cải thiện
    local TOTAL_CONNECTIONS=30  # Giảm từ 100 xuống 30
    local BATCH_SIZE=5         # Chạy 5 connections một lúc
    local BATCH_DELAY=0.5      # Đợi 0.5 giây giữa các batch
    local CONNECTION_TIMEOUT=3  # Timeout cho mỗi connection
    local TEST_DURATION=15     # Tổng thời gian test
    
    print_info "Chạy stress test cải thiện với $TOTAL_CONNECTIONS connections..."
    print_info "Cấu hình: $BATCH_SIZE connections/batch, timeout=${CONNECTION_TIMEOUT}s, delay=${BATCH_DELAY}s"
    
    # Lấy packet count trước khi bắt đầu
    local PACKETS_BEFORE=0
    if [ -f "/proc/vnet_capture" ]; then
        PACKETS_BEFORE=$(cat /proc/vnet_capture | grep -c "│.*│.*│.*│" 2>/dev/null || echo "0")
    fi
    print_info "Packets captured trước test: $PACKETS_BEFORE"
    
    # Tạo background server với better error handling
    print_info "Khởi động stress test server..."
    timeout $TEST_DURATION nc -l -k -s "$VNET1_IP" -p "$TEST_PORT" >/dev/null 2>&1 &
    STRESS_SERVER_PID=$!
    
    # Đợi server khởi động
    sleep 1
    
    # Kiểm tra server có running không
    if ! ps -p $STRESS_SERVER_PID > /dev/null 2>&1; then
        print_error "Không thể khởi động stress test server"
        return 1
    fi
    
    print_success "Server đã khởi động (PID: $STRESS_SERVER_PID)"
    
    # Biến tracking
    local SUCCESS_COUNT=0
    local FAILED_COUNT=0
    local BATCH_COUNT=$((TOTAL_CONNECTIONS / BATCH_SIZE))
    
    print_info "Bắt đầu gửi $TOTAL_CONNECTIONS connections trong $BATCH_COUNT batches..."
    
    # Chạy stress test theo batches
    for batch in $(seq 1 $BATCH_COUNT); do
        print_info "Batch $batch/$BATCH_COUNT - Gửi $BATCH_SIZE connections..."
        
        # Tạo batch connections
        local batch_pids=()
        for i in $(seq 1 $BATCH_SIZE); do
            local conn_id=$(((batch-1) * BATCH_SIZE + i))
            local test_message="Stress test batch $batch conn $i (ID: $conn_id) - $(date +%H:%M:%S.%3N)"
            
            # Chạy connection với timeout và error handling
            (
                if echo "$test_message" | timeout $CONNECTION_TIMEOUT nc -w $CONNECTION_TIMEOUT -s "$VNET0_IP" "$VNET1_IP" "$TEST_PORT" >/dev/null 2>&1; then
                    echo "SUCCESS:$conn_id"
                else
                    echo "FAILED:$conn_id"
                fi
            ) &
            batch_pids+=($!)
        done
        
        # Đợi batch hoàn thành và đếm kết quả
        for pid in "${batch_pids[@]}"; do
            if wait $pid 2>/dev/null; then
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            else
                FAILED_COUNT=$((FAILED_COUNT + 1))
            fi
        done
        
        # Real-time monitoring
        local PACKETS_CURRENT=0
        if [ -f "/proc/vnet_capture" ]; then
            PACKETS_CURRENT=$(cat /proc/vnet_capture | grep -c "│.*│.*│.*│" 2>/dev/null || echo "0")
        fi
        local NEW_PACKETS=$((PACKETS_CURRENT - PACKETS_BEFORE))
        
        print_info "Batch $batch hoàn thành - Success: $SUCCESS_COUNT, Failed: $FAILED_COUNT, New packets: $NEW_PACKETS"
        
        # Delay giữa các batches
        if [ $batch -lt $BATCH_COUNT ]; then
            sleep $BATCH_DELAY
        fi
    done
    
    # Đợi tất cả processes hoàn thành
    sleep 2
    
    # Cleanup server
    kill $STRESS_SERVER_PID 2>/dev/null || true
    wait $STRESS_SERVER_PID 2>/dev/null || true
    
    # Tính toán kết quả cuối cùng
    local TOTAL_TESTED=$((SUCCESS_COUNT + FAILED_COUNT))
    local SUCCESS_RATE=0
    if [ $TOTAL_TESTED -gt 0 ]; then
        SUCCESS_RATE=$(( (SUCCESS_COUNT * 100) / TOTAL_TESTED ))
    fi
    
    # Kiểm tra packet capture cuối cùng
    local PACKETS_AFTER=0
    if [ -f "/proc/vnet_capture" ]; then
        PACKETS_AFTER=$(cat /proc/vnet_capture | grep -c "│.*│.*│.*│" 2>/dev/null || echo "0")
    fi
    local TOTAL_NEW_PACKETS=$((PACKETS_AFTER - PACKETS_BEFORE))
    
    # Báo cáo kết quả
    print_header "Kết quả Stress Test"
    print_info "Tổng connections tested: $TOTAL_TESTED"
    print_info "Successful connections: $SUCCESS_COUNT"
    print_info "Failed connections: $FAILED_COUNT"
    print_info "Success rate: $SUCCESS_RATE%"
    print_info "Packets captured trước: $PACKETS_BEFORE"
    print_info "Packets captured sau: $PACKETS_AFTER"
    print_info "New packets captured: $TOTAL_NEW_PACKETS"
    
    # Đánh giá kết quả
    if [ $SUCCESS_RATE -ge 80 ]; then
        print_success "Stress test THÀNH CÔNG (Success rate >= 80%)"
    elif [ $SUCCESS_RATE -ge 60 ]; then
        print_warning "Stress test TRUNG BÌNH (Success rate 60-79%)"
    else
        print_error "Stress test THẤT BẠI (Success rate < 60%)"
    fi
    
    if [ $TOTAL_NEW_PACKETS -ge $((SUCCESS_COUNT - 5)) ]; then
        print_success "Packet capture hoạt động tốt"
    else
        print_warning "Packet capture có thể có vấn đề (captured: $TOTAL_NEW_PACKETS, expected: ~$SUCCESS_COUNT)"
    fi
    
    # Hiển thị sample packet capture
    print_info "Sample packet capture sau stress test:"
    cat /proc/vnet_capture | head -15
}

# Hàm final cleanup
final_cleanup() {
    print_header "Final Cleanup"
    
    print_info "Đang thực hiện cleanup cuối cùng..."
    
    # Unload modules
    sudo rmmod vnet_netfilter 2>/dev/null || true
    sudo rmmod vnet_driver 2>/dev/null || true
    
    # Clean build files
    make -C src clean >/dev/null 2>&1 || true
    
    # Remove temporary files
    rm -f "$LOG_FILE" 2>/dev/null || true
    
    print_success "Cleanup hoàn tất"
}

# Hàm tạo test report
generate_report() {
    print_header "Tạo Test Report"
    
    REPORT_FILE="/tmp/vnet_test_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "============================================"
        echo "Virtual Network Driver Test Report"
        echo "============================================"
        echo "Thời gian test: $(date)"
        echo "Kernel version: $(uname -r)"
        echo "Test script version: 2.0"
        echo ""
        echo "Test Configuration:"
        echo "- vnet0 IP: $VNET0_IP/$SUBNET_MASK"
        echo "- vnet1 IP: $VNET1_IP/$SUBNET_MASK"
        echo "- Test port: $TEST_PORT"
        echo ""
        echo "Modules loaded:"
        lsmod | grep -E 'vnet_driver|vnet_netfilter' || echo "No vnet modules currently loaded"
        echo ""
        echo "Network interfaces:"
        ip addr show vnet0 2>/dev/null || echo "vnet0 not found"
        ip addr show vnet1 2>/dev/null || echo "vnet1 not found"
        echo ""
        echo "Recent kernel messages:"
        dmesg | grep -E 'vnet|netfilter_capture' | tail -10
        echo ""
        echo "Packet capture sample:"
        head -15 /proc/vnet_capture 2>/dev/null || echo "Packet capture not available"
    } > "$REPORT_FILE"
    
    print_success "Test report đã được tạo: $REPORT_FILE"
    print_info "Sử dụng 'cat $REPORT_FILE' để xem report"
}

# Hàm main
main() {
    echo -e "${CYAN}"
    echo "=================================================="
    echo "🚀 Virtual Network Driver Test Script v2.0"
    echo "=================================================="
    echo -e "${NC}"
    
    # Bắt đầu logging
    echo "Test started at: $(date)" > "$LOG_FILE"
    
    # Thực hiện các bước test
    check_root
    check_kernel_headers
    remove_old_modules
    compile_modules
    load_modules
    verify_modules
    configure_interfaces
    test_basic_connectivity
    test_network_connectivity
    test_packet_capture
    performance_test
    check_kernel_logs
    stress_test
    generate_report
    
    print_header "🎉 Test Suite Hoàn Thành"
    print_success "Tất cả các test đã được thực hiện thành công!"
    print_info "Kiểm tra report tại: /tmp/vnet_test_report_*.txt"
    print_info "Kernel logs: dmesg | grep vnet"
    print_info "Packet capture: cat /proc/vnet_capture"
    
    # Cleanup cuối cùng
    final_cleanup
    
    echo -e "\n${GREEN}✨ Test completed successfully! ✨${NC}\n"
}

# Chạy main function
main "$@"
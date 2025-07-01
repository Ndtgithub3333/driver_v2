#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student - Ndtgithub3333");
MODULE_DESCRIPTION("Netfilter Hook for Virtual Network Packet Capture - Kernel-Safe Version Fixed");
MODULE_VERSION("2.1");

#define PROC_FILENAME "vnet_capture"
#define MAX_CAPTURED_PACKETS 1000

/* Cấu trúc lưu thông tin packet đã bắt - tối ưu cho kernel space */
struct packet_info {
    unsigned long timestamp;        // Thời gian bắt packet (jiffies)
    __be32 src_ip;                 // Source IP address (network byte order)
    __be32 dst_ip;                 // Destination IP address (network byte order)
    __be16 src_port;               // Source port (network byte order)
    __be16 dst_port;               // Destination port (network byte order)
    __u8 protocol;                 // Protocol type (TCP=6, UDP=17, ICMP=1)
    __u16 length;                  // Packet length từ IP header
    char interface[IFNAMSIZ];      // Tên interface bắt packet
    char direction[10];            // Hướng packet: "IN" hoặc "OUT"
    bool is_valid;                 // Flag đánh dấu packet hợp lệ
};

/* Ring buffer structure để quản lý memory hiệu quả - cải thiện từ array tĩnh */
struct packet_ring_buffer {
    struct packet_info *packets;   // Mảng động chứa packet info
    int head;                      // Vị trí đầu của ring buffer (newest)
    int tail;                      // Vị trí cuối của ring buffer (oldest)
    int size;                      // Số lượng packets hiện tại trong buffer
    int max_size;                  // Kích thước tối đa của buffer
    spinlock_t lock;               // Spinlock để đồng bộ hóa multi-threaded access
    bool initialized;              // Flag đánh dấu buffer đã được khởi tạo
};

/* Global ring buffer instance và statistics */
static struct packet_ring_buffer capture_buffer;
static int total_packets = 0;                    // Tổng số packets đã capture từ khi load module
static struct proc_dir_entry *proc_entry;       // Proc filesystem entry

/* Hàm khởi tạo ring buffer với proper error handling */
static int init_packet_ring_buffer(struct packet_ring_buffer *buffer, int max_size)
{
    // Validate input parameters - kiểm tra tính hợp lệ của tham số đầu vào
    if (!buffer || max_size <= 0) {
        printk(KERN_ERR "netfilter_capture: Invalid parameters for ring buffer initialization\n");
        return -EINVAL;
    }

    // Cấp phát memory cho ring buffer - sử dụng kzalloc để zero-initialize
    buffer->packets = kzalloc(max_size * sizeof(struct packet_info), GFP_KERNEL);
    if (!buffer->packets) {
        printk(KERN_ERR "netfilter_capture: Failed to allocate memory for ring buffer (%zu bytes)\n",
               max_size * sizeof(struct packet_info));
        return -ENOMEM;
    }

    // Khởi tạo các giá trị ban đầu của ring buffer
    buffer->head = 0;
    buffer->tail = 0;
    buffer->size = 0;
    buffer->max_size = max_size;
    buffer->initialized = true;
    spin_lock_init(&buffer->lock);

    printk(KERN_INFO "netfilter_capture: ✅ Ring buffer initialized successfully (size: %d packets, memory: %zu bytes)\n", 
           max_size, max_size * sizeof(struct packet_info));
    return 0;
}

/* Hàm cleanup ring buffer để ngăn ngừa memory leak */
static void cleanup_packet_ring_buffer(struct packet_ring_buffer *buffer)
{
    unsigned long flags;

    // Kiểm tra buffer có hợp lệ không
    if (!buffer || !buffer->initialized) {
        return;
    }

    // Acquire lock để đảm bảo thread safety khi cleanup
    spin_lock_irqsave(&buffer->lock, flags);
    
    // Giải phóng allocated memory
    if (buffer->packets) {
        kfree(buffer->packets);
        buffer->packets = NULL;
    }

    // Reset tất cả các giá trị về trạng thái ban đầu
    buffer->head = 0;
    buffer->tail = 0;
    buffer->size = 0;
    buffer->initialized = false;
    
    spin_unlock_irqrestore(&buffer->lock, flags);

    printk(KERN_INFO "netfilter_capture: ✅ Ring buffer cleaned up successfully\n");
}

/* Hàm thêm packet vào ring buffer với thread-safe implementation */
static int add_packet_to_buffer(struct packet_ring_buffer *buffer, const struct packet_info *pkt_info)
{
    unsigned long flags;
    int next_head;

    // Validate input parameters - kiểm tra tính hợp lệ của tham số
    if (!buffer || !buffer->initialized || !pkt_info || !pkt_info->is_valid) {
        return -EINVAL;
    }

    spin_lock_irqsave(&buffer->lock, flags);

    // Tính toán vị trí head tiếp theo trong circular buffer
    next_head = (buffer->head + 1) % buffer->max_size;

    // Nếu buffer đầy, implement circular behavior (overwrite oldest)
    if (buffer->size == buffer->max_size) {
        // Clear old packet data trước khi ghi đè để đảm bảo data integrity
        memset(&buffer->packets[buffer->head], 0, sizeof(struct packet_info));
        buffer->tail = (buffer->tail + 1) % buffer->max_size;
    } else {
        buffer->size++;
    }

    // Copy packet info vào buffer position
    memcpy(&buffer->packets[buffer->head], pkt_info, sizeof(struct packet_info));
    buffer->head = next_head;

    spin_unlock_irqrestore(&buffer->lock, flags);

    return 0;
}

/* Hàm validate IP packet để đảm bảo packet integrity */
static bool is_valid_ip_packet(struct sk_buff *skb)
{
    struct iphdr *ip_header;

    // Kiểm tra SKB có hợp lệ và đủ lớn cho IP header không
    if (!skb || skb->len < sizeof(struct iphdr)) {
        return false;
    }

    // Kiểm tra protocol có phải IP không
    if (skb->protocol != htons(ETH_P_IP)) {
        return false;
    }

    // Lấy và validate IP header
    ip_header = ip_hdr(skb);
    if (!ip_header) {
        return false;
    }

    // Kiểm tra IP version (phải là IPv4)
    if (ip_header->version != 4) {
        return false;
    }

    // Kiểm tra IP header length hợp lệ (tối thiểu 5 words = 20 bytes)
    if (ip_header->ihl < 5) {
        return false;
    }

    // Kiểm tra total length không vượt quá SKB length
    if (ntohs(ip_header->tot_len) > skb->len) {
        return false;
    }

    return true;
}

/* Hàm phân tích và lưu thông tin packet với comprehensive validation */
static void analyze_and_store_packet(struct sk_buff *skb, const char *interface, const char *direction)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct packet_info pkt_info;
    int result;
    
    // Validate tất cả input parameters
    if (!skb || !interface || !direction) {
        printk(KERN_WARNING "netfilter_capture: Invalid parameters in analyze_and_store_packet\n");
        return;
    }

    // Validate IP packet trước khi xử lý
    if (!is_valid_ip_packet(skb)) {
        return; // Bỏ qua packets không hợp lệ
    }
    
    // Initialize packet info structure với zero
    memset(&pkt_info, 0, sizeof(pkt_info));
    
    ip_header = ip_hdr(skb);
    
    // Lưu thông tin cơ bản từ IP header
    pkt_info.timestamp = jiffies;
    pkt_info.src_ip = ip_header->saddr;
    pkt_info.dst_ip = ip_header->daddr;
    pkt_info.protocol = ip_header->protocol;
    pkt_info.length = ntohs(ip_header->tot_len);
    pkt_info.is_valid = true;

    // Copy interface name một cách an toàn
    strncpy(pkt_info.interface, interface, IFNAMSIZ - 1);
    pkt_info.interface[IFNAMSIZ - 1] = '\0';

    // Copy direction string một cách an toàn
    strncpy(pkt_info.direction, direction, sizeof(pkt_info.direction) - 1);
    pkt_info.direction[sizeof(pkt_info.direction) - 1] = '\0';
    
    // Extract port information cho TCP/UDP với validation
    pkt_info.src_port = 0;
    pkt_info.dst_port = 0;
    
    if (ip_header->protocol == IPPROTO_TCP) {
        // Kiểm tra có đủ data cho TCP header không
        if (skb->len >= (ip_header->ihl * 4) + sizeof(struct tcphdr)) {
            tcp_header = tcp_hdr(skb);
            if (tcp_header) {
                pkt_info.src_port = ntohs(tcp_header->source);
                pkt_info.dst_port = ntohs(tcp_header->dest);
            }
        }
    } else if (ip_header->protocol == IPPROTO_UDP) {
        // Kiểm tra có đủ data cho UDP header không
        if (skb->len >= (ip_header->ihl * 4) + sizeof(struct udphdr)) {
            udp_header = udp_hdr(skb);
            if (udp_header) {
                pkt_info.src_port = ntohs(udp_header->source);
                pkt_info.dst_port = ntohs(udp_header->dest);
            }
        }
    }
    
    // Thêm packet vào ring buffer
    result = add_packet_to_buffer(&capture_buffer, &pkt_info);
    if (result == 0) {
        total_packets++;
        printk(KERN_INFO "netfilter_capture: 📦 Captured packet %s on %s: %pI4:%d -> %pI4:%d (protocol: %d, len: %d)\n",
               direction, interface,
               &pkt_info.src_ip, pkt_info.src_port,
               &pkt_info.dst_ip, pkt_info.dst_port,
               pkt_info.protocol, pkt_info.length);
    } else {
        printk(KERN_WARNING "netfilter_capture: Failed to store packet (error: %d)\n", result);
    }
}

/* Hook function cho INPUT chain - capture incoming packets */
static unsigned int hook_func_in(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    // Validate hook state và input interface
    if (!state || !state->in) {
        return NF_ACCEPT;
    }

    // Chỉ capture packets từ virtual interfaces của chúng ta
    if (strncmp(state->in->name, "vnet", 4) == 0) {
        analyze_and_store_packet(skb, state->in->name, "IN");
    }
    
    return NF_ACCEPT; /* Luôn cho phép packet đi tiếp */
}

/* Hook function cho OUTPUT chain - capture outgoing packets */
static unsigned int hook_func_out(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    // Validate hook state và output interface
    if (!state || !state->out) {
        return NF_ACCEPT;
    }

    // Chỉ capture packets từ virtual interfaces của chúng ta
    if (strncmp(state->out->name, "vnet", 4) == 0) {
        analyze_and_store_packet(skb, state->out->name, "OUT");
    }
    
    return NF_ACCEPT; /* Luôn cho phép packet đi tiếp */
}

/* Cấu trúc netfilter hooks cho INPUT và OUTPUT chains */
static struct nf_hook_ops netfilter_ops_in = {
    .hook = hook_func_in,
    .hooknum = NF_INET_LOCAL_IN,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops netfilter_ops_out = {
    .hook = hook_func_out,
    .hooknum = NF_INET_LOCAL_OUT,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};

/* Hàm tính percentage mà không dùng floating point - kernel-safe 
 * Đổi tên tham số để tránh xung đột với kernel macro 'current' */
static int calculate_usage_percentage(int current_count, int total_count)
{
    // Kiểm tra division by zero
    if (total_count == 0) {
        return 0;
    }
    // Sử dụng integer arithmetic thay vì floating point
    // (current_count * 100) / total_count cho kết quả phần trăm
    return (current_count * 100) / total_count;
}

/* Hàm hiển thị thông tin trong /proc với improved formatting và kernel-safe operations */
static int proc_show(struct seq_file *m, void *v)
{
    int i, current_size;
    struct packet_info *pkt;
    unsigned long flags;
    char protocol_name[8];
    char src_ip_str[16], dst_ip_str[16];
    int usage_percentage;

    // Header với Unicode symbols và thông tin tổng quan
    seq_puts(m, "================== Virtual Network Packet Capture Statistics ==================\n");
    seq_printf(m, "📊 Total packets captured: %d\n", total_packets);
    
    spin_lock_irqsave(&capture_buffer.lock, flags);
    current_size = capture_buffer.size;
    
    // Tính percentage sử dụng integer arithmetic (kernel-safe)
    // Đổi tên biến để tránh xung đột với kernel macro
    usage_percentage = calculate_usage_percentage(current_size, capture_buffer.max_size);
    
    seq_printf(m, "💾 Current buffer usage: %d/%d packets (%d%%)\n", 
               current_size, capture_buffer.max_size, usage_percentage);
    
    if (current_size == 0) {
        spin_unlock_irqrestore(&capture_buffer.lock, flags);
        seq_puts(m, "\n🔍 No packets captured yet. Waiting for network activity...\n");
        seq_puts(m, "💡 Try: ping -I vnet0 192.168.10.2 (if interfaces are configured)\n");
        seq_puts(m, "💡 Or: nc -s 192.168.10.1 192.168.10.2 12345\n");
        return 0;
    }
    
    seq_puts(m, "\n");
    // Tạo table header với box drawing characters để hiển thị đẹp
    seq_puts(m, "┌────────────┬─────┬─────────────────┬───────┬─────────────────┬───────┬───────┬──────┬───────────┐\n");
    seq_puts(m, "│ Timestamp  │ Dir │   Source IP     │ SPort │     Dest IP     │ DPort │ Proto │ Len  │   Iface   │\n");
    seq_puts(m, "├────────────┼─────┼─────────────────┼───────┼─────────────────┼───────┼───────┼──────┼───────────┤\n");

    // Hiển thị packets từ tail đến head (oldest to newest) cho chronological order
    for (i = 0; i < current_size; i++) {
        int idx = (capture_buffer.tail + i) % capture_buffer.max_size;
        pkt = &capture_buffer.packets[idx];

        // Skip invalid packets để đảm bảo data integrity
        if (!pkt->is_valid) {
            continue;
        }

        // Convert protocol number thành human-readable string
        switch (pkt->protocol) {
            case IPPROTO_TCP:
                strcpy(protocol_name, "TCP");
                break;
            case IPPROTO_UDP:
                strcpy(protocol_name, "UDP");
                break;
            case IPPROTO_ICMP:
                strcpy(protocol_name, "ICMP");
                break;
            default:
                snprintf(protocol_name, sizeof(protocol_name), "%u", pkt->protocol);
                break;
        }

        // Convert IP addresses từ network byte order sang readable format
        snprintf(src_ip_str, sizeof(src_ip_str), "%pI4", &pkt->src_ip);
        snprintf(dst_ip_str, sizeof(dst_ip_str), "%pI4", &pkt->dst_ip);

        // Format output với perfect alignment cho table structure
        seq_printf(m,
            "│ %10lu │ %-3s │ %15s │ %5u │ %15s │ %5u │ %5s │ %4u │ %-9s │\n",
            pkt->timestamp,
            pkt->direction,
            src_ip_str,
            pkt->src_port,
            dst_ip_str,
            pkt->dst_port,
            protocol_name,
            pkt->length,
            pkt->interface
        );
    }

    spin_unlock_irqrestore(&capture_buffer.lock, flags);

    // Table footer
    seq_puts(m, "└────────────┴─────┴─────────────────┴───────┴─────────────────┴───────┴───────┴──────┴───────────┘\n");
    
    // Helpful tips cho user
    seq_puts(m, "\n💡 Tips:\n");
    seq_puts(m, "   - Use 'dmesg | grep netfilter_capture' để xem detailed logs\n");
    seq_puts(m, "   - Timestamps are in jiffies (kernel time ticks)\n");
    seq_puts(m, "   - Buffer size: ");
    seq_printf(m, "%d packets (circular buffer)\n", capture_buffer.max_size);
    seq_puts(m, "   - To convert jiffies to seconds: jiffies / HZ\n");
    seq_puts(m, "   - Current HZ value: ");
    seq_printf(m, "%d\n", HZ);

    return 0;
}

/* Hàm mở proc file */
static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

/* Proc file operations structure cho kernel interface */
static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* Hàm khởi tạo module với comprehensive error handling */
static int __init vnet_netfilter_init(void)
{
    int ret;
    
    printk(KERN_INFO "netfilter_capture: 🚀 Starting Netfilter Hook initialization v2.1\n");
    
    // Khởi tạo ring buffer trước khi đăng ký hooks
    ret = init_packet_ring_buffer(&capture_buffer, MAX_CAPTURED_PACKETS);
    if (ret) {
        printk(KERN_ERR "netfilter_capture: Failed to initialize ring buffer (error: %d)\n", ret);
        return ret;
    }
    
    // Tạo proc entry để user space có thể đọc statistics
    proc_entry = proc_create(PROC_FILENAME, 0444, NULL, &proc_fops);
    if (!proc_entry) {
        printk(KERN_ERR "netfilter_capture: Failed to create proc entry /proc/%s\n", PROC_FILENAME);
        cleanup_packet_ring_buffer(&capture_buffer);
        return -ENOMEM;
    }
    
    // Đăng ký netfilter hook cho INPUT chain
    ret = nf_register_net_hook(&init_net, &netfilter_ops_in);
    if (ret) {
        printk(KERN_ERR "netfilter_capture: Failed to register INPUT hook (error: %d)\n", ret);
        proc_remove(proc_entry);
        cleanup_packet_ring_buffer(&capture_buffer);
        return ret;
    }
    
    // Đăng ký netfilter hook cho OUTPUT chain
    ret = nf_register_net_hook(&init_net, &netfilter_ops_out);
    if (ret) {
        printk(KERN_ERR "netfilter_capture: Failed to register OUTPUT hook (error: %d)\n", ret);
        nf_unregister_net_hook(&init_net, &netfilter_ops_in);
        proc_remove(proc_entry);
        cleanup_packet_ring_buffer(&capture_buffer);
        return ret;
    }
    
    // Success logging với useful information
    printk(KERN_INFO "netfilter_capture: ✅ Initialization successful\n");
    printk(KERN_INFO "netfilter_capture: 📊 View statistics at /proc/%s\n", PROC_FILENAME);
    printk(KERN_INFO "netfilter_capture: 💾 Ring buffer size: %d packets\n", MAX_CAPTURED_PACKETS);
    printk(KERN_INFO "netfilter_capture: 🎯 Monitoring virtual network interfaces (vnet*)\n");
    printk(KERN_INFO "netfilter_capture: ⏰ System HZ value: %d (for jiffies conversion)\n", HZ);
    
    return 0;
}

/* Hàm cleanup module với thorough resource deallocation */
static void __exit vnet_netfilter_exit(void)
{
    printk(KERN_INFO "netfilter_capture: 🧹 Starting cleanup process\n");
    
    // Unregister netfilter hooks trước để stop capturing
    nf_unregister_net_hook(&init_net, &netfilter_ops_in);
    nf_unregister_net_hook(&init_net, &netfilter_ops_out);
    printk(KERN_INFO "netfilter_capture: ✅ Netfilter hooks unregistered\n");
    
    // Remove proc entry để ngăn user space access
    proc_remove(proc_entry);
    printk(KERN_INFO "netfilter_capture: ✅ Proc entry /proc/%s removed\n", PROC_FILENAME);
    
    // Cleanup ring buffer cuối cùng để giải phóng memory
    cleanup_packet_ring_buffer(&capture_buffer);
    printk(KERN_INFO "netfilter_capture: ✅ Ring buffer cleaned up\n");
    
    // Final statistics
    printk(KERN_INFO "netfilter_capture: 📊 Total packets captured during session: %d\n", total_packets);
    printk(KERN_INFO "netfilter_capture: 🎯 Cleanup completed successfully\n");
}

module_init(vnet_netfilter_init);
module_exit(vnet_netfilter_exit);
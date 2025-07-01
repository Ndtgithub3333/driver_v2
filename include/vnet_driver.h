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
#define VNET_MAX_PACKET_SIZE 1500          // Kích thước packet tối đa (MTU)
#define VNET_STATS_PROC_NAME "vnet_stats"  // Tên file proc cho statistics
#define VNET_MAX_CAPTURED_PACKETS 10000    // Số lượng packet tối đa được capture

/* Thu gọn struct vnet_priv - loại bỏ fields ít sử dụng */
struct vnet_priv {
    struct net_device_stats stats;    /* Thống kê network device */
    struct net_device *peer;          /* Interface đối tác */
    spinlock_t lock;                  /* Lock đồng bộ hóa */
    char name[IFNAMSIZ];             /* Tên interface */
    int id;                          /* ID của interface */
    bool is_active;                   /* Trạng thái hoạt động */
};

/* Thu gọn struct captured_packet - loại bỏ fields redundant */
struct captured_packet {
    struct list_head list;            /* Node trong linked list */
    char interface_name[IFNAMSIZ];    /* Tên interface */
    unsigned long timestamp;          /* Timestamp */
    __be32 src_ip;                   /* Source IP */
    __be32 dst_ip;                   /* Destination IP */
    __u8 protocol;                   /* Protocol type */
    __u16 packet_size;               /* Kích thước packet */
    bool is_valid;                   /* Flag hợp lệ */
};

/* Cấu trúc để tracking performance metrics cho monitoring */
struct vnet_performance_stats {
    atomic_t total_packets_forwarded; /* Tổng số packets đã forward thành công */
    atomic_t total_bytes_forwarded;   /* Tổng số bytes đã forward */
    atomic_t packets_dropped;         /* Số packets bị drop do lỗi hoặc overload */
    atomic_t memory_allocation_failures; /* Số lần cấp phát memory thất bại */
    unsigned long last_reset_time;    /* Thời gian reset statistics cuối cùng */
};

/* Khai báo biến toàn cục - sẽ được định nghĩa trong source file */
extern struct net_device *vnet_devices[2];  /* Mảng chứa 2 network devices */
extern struct list_head captured_packets;   /* Danh sách packets đã capture */
extern spinlock_t capture_lock;              /* Lock cho captured packets list */
extern int packet_count;                     /* Đếm số packets hiện tại */
extern struct vnet_performance_stats perf_stats; /* Performance statistics */

/* Khai báo hàm chính - các hàm network device operations */
int vnet_open(struct net_device *dev);
int vnet_close(struct net_device *dev);
netdev_tx_t vnet_start_xmit(struct sk_buff *skb, struct net_device *dev);
struct net_device_stats *vnet_get_stats(struct net_device *dev);
void vnet_cleanup(void);

/* Khai báo hàm debug và monitoring cho development */
void vnet_print_device_stats(struct net_device *dev);
void vnet_reset_performance_stats(void);
void vnet_print_performance_stats(void);

/* Inline functions để tối ưu performance - compile-time optimization */
static inline bool vnet_is_virtual_interface(const char *name)
{
    /* Kiểm tra xem interface có phải là virtual interface của chúng ta không */
    return (strncmp(name, "vnet", 4) == 0);
}

static inline unsigned long vnet_get_uptime_ms(unsigned long start_jiffies)
{
    /* Tính thời gian uptime tính từ start_jiffies đến hiện tại */
    return jiffies_to_msecs(jiffies - start_jiffies);
}

/* Macros để logging với different levels - giúp debug dễ dàng hơn */
#ifdef DEBUG
#define vnet_debug(fmt, ...) \
    printk(KERN_DEBUG "vnet_debug: " fmt, ##__VA_ARGS__)
#else
#define vnet_debug(fmt, ...) \
    do { } while (0)  /* No-op khi không ở debug mode */
#endif

#define vnet_info(fmt, ...) \
    printk(KERN_INFO "vnet: " fmt, ##__VA_ARGS__)

#define vnet_warning(fmt, ...) \
    printk(KERN_WARNING "vnet: " fmt, ##__VA_ARGS__)

#define vnet_error(fmt, ...) \
    printk(KERN_ERR "vnet: " fmt, ##__VA_ARGS__)

/* Version information cho module */
#define VNET_DRIVER_VERSION "2.0"
#define VNET_DRIVER_NAME "Virtual Network Driver"
#define VNET_DRIVER_DESCRIPTION "Virtual Network Driver with Enhanced Packet Capture"

#endif /* VNET_DRIVER_H */
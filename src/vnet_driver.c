#include "../include/vnet_driver.h"
#include <linux/version.h>
#include <linux/etherdevice.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Student - Ndtgithub3333");
MODULE_DESCRIPTION("Virtual Network Driver with Packet Capture - Fixed Version");
MODULE_VERSION("2.0");

/* Biến toàn cục - được export để netfilter module có thể sử dụng */
struct net_device *vnet_devices[2];
struct list_head captured_packets;
spinlock_t capture_lock;
int packet_count = 0;

/* Atomic counters để tracking performance một cách thread-safe */
static atomic_t total_packets_sent = ATOMIC_INIT(0);
static atomic_t total_packets_received = ATOMIC_INIT(0);

/* Thu gọn hàm validate device state */
static bool is_device_ready(struct net_device *dev)
{
    return dev && netif_device_present(dev) && netif_running(dev);
}

/* Thu gọn hàm mở interface */
int vnet_open(struct net_device *dev)
{
    struct vnet_priv *priv;

    if (!dev || !(priv = netdev_priv(dev)))
        return -EINVAL;

    vnet_info("Mở interface %s\n", dev->name);
    
    netif_start_queue(dev);
    memset(&priv->stats, 0, sizeof(priv->stats));
    priv->is_active = true;

    return 0;
}

/* Thu gọn hàm đóng interface */
int vnet_close(struct net_device *dev)
{
    struct vnet_priv *priv;

    if (!dev)
        return -EINVAL;

    priv = netdev_priv(dev);
    vnet_info("Đóng interface %s\n", dev->name);

    netif_stop_queue(dev);
    netif_tx_disable(dev);
    
    if (priv)
        priv->is_active = false;

    return 0;
}

/* Hàm validate SKB trước khi xử lý - đảm bảo packet hợp lệ */
static bool is_valid_skb(struct sk_buff *skb, struct net_device *dev)
{
    /* Kiểm tra SKB pointer */
    if (!skb) {
        vnet_error("SKB is NULL\n");
        return false;
    }

    /* Kiểm tra device pointer */
    if (!dev) {
        vnet_error("Device is NULL\n");
        return false;
    }

    /* Kiểm tra packet không rỗng */
    if (skb->len == 0) {
        vnet_warning("Empty packet detected on %s\n", dev->name);
        return false;
    }

    /* Kiểm tra packet size không vượt quá MTU */
    if (skb->len > VNET_MAX_PACKET_SIZE) {
        vnet_warning("Packet too large on %s (%d bytes > %d MTU)\n", 
                    dev->name, skb->len, VNET_MAX_PACKET_SIZE);
        return false;
    }

    return true;
}

/* Hàm tạo captured packet entry với improved error handling */
static int create_captured_packet(struct sk_buff *skb, struct net_device *dev, int direction)
{
    struct captured_packet *cap_pkt;
    unsigned long flags;

    /* Validate input parameters */
    if (!skb || !dev) {
        vnet_error("Invalid parameters for packet capture\n");
        return -EINVAL;
    }

    /* Cấp phát memory cho captured packet structure */
    cap_pkt = kzalloc(sizeof(struct captured_packet), GFP_ATOMIC);
    if (!cap_pkt) {
        vnet_warning("Failed to allocate memory for captured packet\n");
        return -ENOMEM;
    }

    /* Thu gọn captured packet */
    strncpy(cap_pkt->interface_name, dev->name, IFNAMSIZ - 1);
    cap_pkt->timestamp = jiffies;
    cap_pkt->packet_size = skb->len;
    cap_pkt->is_valid = true;

    /* Thu gọn IP info nếu có */
    if (skb->protocol == htons(ETH_P_IP)) {
        struct iphdr *iph = ip_hdr(skb);
        if (iph) {
            cap_pkt->src_ip = iph->saddr;
            cap_pkt->dst_ip = iph->daddr;
            cap_pkt->protocol = iph->protocol;
        }
    }

    /* Thêm vào capture list với thread safety */
    spin_lock_irqsave(&capture_lock, flags);
    
    /* Implement circular buffer behavior để tránh memory overflow */
    if (packet_count >= VNET_MAX_CAPTURED_PACKETS) {
        struct captured_packet *old_pkt = list_first_entry(&captured_packets, 
                                                           struct captured_packet, list);
        list_del(&old_pkt->list);
        /* Thu gọn cleanup - không cần SKB reference */
        kfree(old_pkt);
        packet_count--;
    }

    /* Thêm packet mới vào cuối danh sách */
    list_add_tail(&cap_pkt->list, &captured_packets);
    packet_count++;
    
    spin_unlock_irqrestore(&capture_lock, flags);

    vnet_debug("📦 Captured packet from %s (size: %u bytes, total captured: %d)\n",
               dev->name, skb->len, packet_count);

    return 0;
}

/* Hàm xử lý truyền gói tin - core functionality của driver */
netdev_tx_t vnet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);
    struct vnet_priv *peer_priv;
    struct sk_buff *new_skb;
    unsigned long flags;
    int capture_result;

    /* Validate inputs thoroughly */
    if (!is_valid_skb(skb, dev)) {
        vnet_warning("Invalid SKB, dropping packet\n");
        goto drop_packet;
    }

    if (!is_device_ready(dev)) {
        vnet_warning("Device %s is not ready for transmission\n", dev->name);
        goto drop_packet;
    }

    /* Kiểm tra peer device có tồn tại và sẵn sàng không */
    if (!priv->peer) {
        vnet_error("No peer device configured for %s\n", dev->name);
        goto drop_packet;
    }

    if (!is_device_ready(priv->peer)) {
        vnet_warning("Peer device %s is not ready\n", priv->peer->name);
        goto drop_packet;
    }

    peer_priv = netdev_priv(priv->peer);
    if (!peer_priv) {
        vnet_error("Peer private data is NULL\n");
        goto drop_packet;
    }

    /* Capture packet cho debugging/monitoring (non-blocking) */
    capture_result = create_captured_packet(skb, dev, priv->id);
    if (capture_result != 0 && capture_result != -ENOMEM) {
        vnet_warning("Failed to capture packet (error: %d), continuing transmission\n", capture_result);
        /* Tiếp tục forward packet dù capture thất bại */
    }

    /* Tạo copy của SKB để forward - ưu tiên clone trước, fallback to copy */
    new_skb = skb_clone(skb, GFP_ATOMIC);
    if (!new_skb) {
        /* Fallback to copy nếu clone thất bại */
        new_skb = skb_copy(skb, GFP_ATOMIC);
        if (!new_skb) {
            vnet_error("Failed to clone/copy SKB for transmission\n");
            goto drop_packet;
        }
        vnet_debug("Used skb_copy as fallback (less efficient)\n");
    } else {
        vnet_debug("Used skb_clone for efficiency\n");
    }

    /* Cấu hình SKB cho peer device */
    new_skb->dev = priv->peer;
    
    /* Reset header pointers để đảm bảo consistency */
    skb_reset_mac_header(new_skb);
    skb_reset_network_header(new_skb);
    skb_reset_transport_header(new_skb);
    
    /* Thiết lập protocol cho network stack */
    new_skb->protocol = eth_type_trans(new_skb, priv->peer);
    
    /* Cấu hình checksum handling theo kernel version */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
    new_skb->ip_summed = CHECKSUM_UNNECESSARY;
#else
    new_skb->ip_summed = CHECKSUM_NONE;
#endif

    /* Cập nhật statistics cho sender device */
    spin_lock_irqsave(&priv->lock, flags);
    priv->stats.tx_packets++;
    priv->stats.tx_bytes += skb->len;
    spin_unlock_irqrestore(&priv->lock, flags);

    /* Cập nhật statistics cho receiver device */
    spin_lock_irqsave(&peer_priv->lock, flags);
    peer_priv->stats.rx_packets++;
    peer_priv->stats.rx_bytes += new_skb->len;
    spin_unlock_irqrestore(&peer_priv->lock, flags);

    /* Update global atomic counters */
    atomic_inc(&total_packets_sent);
    atomic_inc(&total_packets_received);

    /* Gửi packet lên network stack của peer device */
    if (netif_rx(new_skb) == NET_RX_DROP) {
        vnet_warning("netif_rx dropped packet on %s\n", priv->peer->name);
        /* Statistics đã được update, không cần rollback */
    }

    /* Giải phóng SKB gốc */
    dev_kfree_skb(skb);

    vnet_debug("✅ Successfully forwarded packet from %s to %s (size: %u bytes)\n",
               dev->name, priv->peer->name, new_skb->len);

    return NETDEV_TX_OK;

drop_packet:
    /* Cập nhật drop statistics */
    if (priv) {
        spin_lock_irqsave(&priv->lock, flags);
        priv->stats.tx_dropped++;
        spin_unlock_irqrestore(&priv->lock, flags);
    }
    
    /* Giải phóng SKB */
    dev_kfree_skb(skb);
    vnet_warning("❌ Dropped packet on %s\n", dev ? dev->name : "unknown");
    return NETDEV_TX_OK;
}

/* Hàm lấy network statistics */
struct net_device_stats *vnet_get_stats(struct net_device *dev)
{
    struct vnet_priv *priv;
    
    if (!dev) {
        vnet_error("Cannot get stats for NULL device\n");
        return NULL;
    }
    
    priv = netdev_priv(dev);
    if (!priv) {
        vnet_error("Private data is NULL for device %s\n", dev->name);
        return NULL;
    }

    /* Log detailed statistics periodically để monitoring */
    if ((priv->stats.tx_packets + priv->stats.rx_packets) % 1000 == 0 && 
        (priv->stats.tx_packets + priv->stats.rx_packets) > 0) {
        vnet_info("📊 Stats for %s - TX: %lu pkts (%lu bytes, %lu dropped), RX: %lu pkts (%lu bytes)\n",
               dev->name, priv->stats.tx_packets, priv->stats.tx_bytes, priv->stats.tx_dropped,
               priv->stats.rx_packets, priv->stats.rx_bytes);
    }

    return &priv->stats;
}

/* Network device operations structure */
static const struct net_device_ops vnet_netdev_ops = {
    .ndo_open = vnet_open,
    .ndo_stop = vnet_close,
    .ndo_start_xmit = vnet_start_xmit,
    .ndo_get_stats = vnet_get_stats,
};

/* Hàm setup network device với optimized configuration */
static void vnet_setup(struct net_device *dev)
{
    struct vnet_priv *priv;

    if (!dev) {
        vnet_error("Cannot setup NULL device\n");
        return;
    }

    /* Setup cơ bản cho ethernet device */
    ether_setup(dev);

    /* Assign operations cho device */
    dev->netdev_ops = &vnet_netdev_ops;

    /* Cấu hình flags để optimize cho virtual networking */
    dev->flags |= IFF_NOARP;          /* Không cần ARP protocol */
    dev->flags |= IFF_POINTOPOINT;    /* Point-to-point connection */
    
    /* Feature flags để optimize performance */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
    dev->features |= NETIF_F_HW_CSUM;         /* Hardware checksum support */
    dev->features |= NETIF_F_SG;              /* Scatter-gather I/O */
    dev->features |= NETIF_F_FRAGLIST;        /* Fragment list support */
#else
    dev->features |= NETIF_F_NO_CSUM;         /* No checksum needed */
#endif

    /* Cấu hình MTU và header sizes */
    dev->mtu = VNET_MAX_PACKET_SIZE;
    dev->hard_header_len = ETH_HLEN;
    dev->addr_len = ETH_ALEN;

    /* Khởi tạo private data structure */
    priv = netdev_priv(dev);
    if (priv) {
        memset(priv, 0, sizeof(struct vnet_priv));
        spin_lock_init(&priv->lock);
        priv->peer = NULL;
        priv->id = -1;
        priv->is_active = false;
    }

    /* Generate random MAC address cho mỗi interface */
    eth_random_addr(dev->dev_addr);

    vnet_info("⚙️ Device %s configured with MAC: %pM\n", dev->name, dev->dev_addr);
}

/* Module initialization function */
static int __init vnet_init(void)
{
    int ret = 0;
    struct vnet_priv *priv0, *priv1;

    vnet_info("🚀 Starting Virtual Network Driver v2.0 initialization\n");

    /* Khởi tạo global data structures */
    INIT_LIST_HEAD(&captured_packets);
    spin_lock_init(&capture_lock);

    /* Reset global counters */
    atomic_set(&total_packets_sent, 0);
    atomic_set(&total_packets_received, 0);

    /* Tạo và cấp phát device đầu tiên (vnet0) */
    vnet_devices[0] = alloc_netdev(sizeof(struct vnet_priv),
                                   VNET_DEVICE_NAME_A,
                                   NET_NAME_ENUM,
                                   vnet_setup);
    if (!vnet_devices[0]) {
        vnet_error("❌ Failed to allocate memory for %s\n", VNET_DEVICE_NAME_A);
        return -ENOMEM;
    }

    /* Tạo và cấp phát device thứ hai (vnet1) */
    vnet_devices[1] = alloc_netdev(sizeof(struct vnet_priv),
                                   VNET_DEVICE_NAME_B,
                                   NET_NAME_ENUM,
                                   vnet_setup);
    if (!vnet_devices[1]) {
        vnet_error("❌ Failed to allocate memory for %s\n", VNET_DEVICE_NAME_B);
        free_netdev(vnet_devices[0]);
        vnet_devices[0] = NULL;
        return -ENOMEM;
    }

    /* Thiết lập peer relationship giữa hai devices */
    priv0 = netdev_priv(vnet_devices[0]);
    priv1 = netdev_priv(vnet_devices[1]);

    if (!priv0 || !priv1) {
        vnet_error("❌ Failed to get private data for devices\n");
        free_netdev(vnet_devices[0]);
        free_netdev(vnet_devices[1]);
        return -ENOMEM;
    }

    /* Configure peer relationships và IDs */
    priv0->peer = vnet_devices[1];
    priv1->peer = vnet_devices[0];
    priv0->id = 0;
    priv1->id = 1;
    strncpy(priv0->name, VNET_DEVICE_NAME_A, IFNAMSIZ - 1);
    strncpy(priv1->name, VNET_DEVICE_NAME_B, IFNAMSIZ - 1);
    priv0->name[IFNAMSIZ - 1] = '\0';
    priv1->name[IFNAMSIZ - 1] = '\0';

    /* Đăng ký device đầu tiên với kernel */
    ret = register_netdev(vnet_devices[0]);
    if (ret) {
        vnet_error("❌ Failed to register %s, error: %d\n", VNET_DEVICE_NAME_A, ret);
        free_netdev(vnet_devices[0]);
        free_netdev(vnet_devices[1]);
        vnet_devices[0] = NULL;
        vnet_devices[1] = NULL;
        return ret;
    }

    /* Đăng ký device thứ hai với kernel */
    ret = register_netdev(vnet_devices[1]);
    if (ret) {
        vnet_error("❌ Failed to register %s, error: %d\n", VNET_DEVICE_NAME_B, ret);
        unregister_netdev(vnet_devices[0]);
        free_netdev(vnet_devices[0]);
        free_netdev(vnet_devices[1]);
        vnet_devices[0] = NULL;
        vnet_devices[1] = NULL;
        return ret;
    }

    /* Success logging */
    vnet_info("✅ Successfully initialized 2 virtual network interfaces\n");
    vnet_info("🔗 Connection established: %s <-> %s\n", VNET_DEVICE_NAME_A, VNET_DEVICE_NAME_B);
    vnet_info("📊 Use 'cat /proc/net/dev' to view interface statistics\n");
    vnet_info("🔍 Use 'dmesg | grep vnet' to view detailed logs\n");

    return 0;
}

/* Cleanup function khi unload module */
void vnet_cleanup(void)
{
    struct captured_packet *cap_pkt, *tmp;
    unsigned long flags;
    int final_sent, final_received;

    vnet_info("🧹 Starting Virtual Network Driver cleanup\n");

    /* Lấy final statistics trước khi cleanup */
    final_sent = atomic_read(&total_packets_sent);
    final_received = atomic_read(&total_packets_received);

    /* Unregister và free network devices */
    if (vnet_devices[0]) {
        struct vnet_priv *priv0 = netdev_priv(vnet_devices[0]);
        if (priv0) {
            vnet_info("Final stats for %s - TX: %lu, RX: %lu\n",
                   vnet_devices[0]->name, priv0->stats.tx_packets, priv0->stats.rx_packets);
        }
        unregister_netdev(vnet_devices[0]);
        free_netdev(vnet_devices[0]);
        vnet_devices[0] = NULL;
        vnet_info("✅ Cleaned up %s\n", VNET_DEVICE_NAME_A);
    }

    if (vnet_devices[1]) {
        struct vnet_priv *priv1 = netdev_priv(vnet_devices[1]);
        if (priv1) {
            vnet_info("Final stats for %s - TX: %lu, RX: %lu\n",
                   vnet_devices[1]->name, priv1->stats.tx_packets, priv1->stats.rx_packets);
        }
        unregister_netdev(vnet_devices[1]);
        free_netdev(vnet_devices[1]);
        vnet_devices[1] = NULL;
        vnet_info("✅ Cleaned up %s\n", VNET_DEVICE_NAME_B);
    }

    /* Cleanup captured packets list với proper memory management */
    spin_lock_irqsave(&capture_lock, flags);
    list_for_each_entry_safe(cap_pkt, tmp, &captured_packets, list) {
        list_del(&cap_pkt->list);
        /* Thu gọn cleanup - không cần SKB reference */
        kfree(cap_pkt);
    }
    vnet_info("✅ Cleaned up %d captured packets\n", packet_count);
    packet_count = 0;
    spin_unlock_irqrestore(&capture_lock, flags);

    /* Print final global statistics */
    vnet_info("📊 Final global statistics:\n");
    vnet_info("    Total packets sent: %d\n", final_sent);
    vnet_info("    Total packets received: %d\n", final_received);

    vnet_info("🎯 Virtual Network Driver cleanup completed successfully\n");
}

/* Module exit function */
static void __exit vnet_exit(void)
{
    vnet_cleanup();
}

module_init(vnet_init);
module_exit(vnet_exit);
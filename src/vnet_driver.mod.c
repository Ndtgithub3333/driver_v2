#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_MITIGATION_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const char ____versions[]
__used __section("__versions") =
	"\x1c\x00\x00\x00\x08\xdf\xf4\xca"
	"alloc_netdev_mqs\0\0\0\0"
	"\x18\x00\x00\x00\x89\x15\x43\x4e"
	"register_netdev\0"
	"\x14\x00\x00\x00\xfc\xf8\x96\xd6"
	"free_netdev\0"
	"\x1c\x00\x00\x00\x51\xa0\xce\xac"
	"unregister_netdev\0\0\0"
	"\x14\x00\x00\x00\xfc\xef\x04\xf0"
	"ether_setup\0"
	"\x1c\x00\x00\x00\x09\x37\xed\x41"
	"get_random_bytes\0\0\0\0"
	"\x1c\x00\x00\x00\x63\xa5\x03\x4c"
	"random_kmalloc_seed\0"
	"\x18\x00\x00\x00\x95\x43\xcb\xf3"
	"kmalloc_caches\0\0"
	"\x20\x00\x00\x00\x56\x45\x8f\xe4"
	"__kmalloc_cache_noprof\0\0"
	"\x10\x00\x00\x00\xda\xfa\x66\x91"
	"strncpy\0"
	"\x10\x00\x00\x00\xa6\x50\xba\x15"
	"jiffies\0"
	"\x20\x00\x00\x00\x0b\x05\xdb\x34"
	"_raw_spin_lock_irqsave\0\0"
	"\x24\x00\x00\x00\x70\xce\x5c\xd3"
	"_raw_spin_unlock_irqrestore\0"
	"\x14\x00\x00\x00\xa6\xce\x1b\x77"
	"skb_clone\0\0\0"
	"\x18\x00\x00\x00\xb8\x23\x67\x28"
	"eth_type_trans\0\0"
	"\x14\x00\x00\x00\xf7\xdb\x99\xb2"
	"netif_rx\0\0\0\0"
	"\x14\x00\x00\x00\xe9\x29\x6f\x62"
	"consume_skb\0"
	"\x10\x00\x00\x00\xba\x0c\x7a\x03"
	"kfree\0\0\0"
	"\x14\x00\x00\x00\xdc\x93\x96\x75"
	"skb_copy\0\0\0\0"
	"\x14\x00\x00\x00\xba\x46\x1d\x55"
	"pcpu_hot\0\0\0\0"
	"\x18\x00\x00\x00\x64\xbd\x8f\xba"
	"_raw_spin_lock\0\0"
	"\x10\x00\x00\x00\xbd\xb4\x94\x02"
	"pv_ops\0\0"
	"\x14\x00\x00\x00\xe6\x10\xec\xd4"
	"BUG_func\0\0\0\0"
	"\x20\x00\x00\x00\x39\xce\x3f\x3c"
	"__local_bh_enable_ip\0\0\0\0"
	"\x14\x00\x00\x00\xbb\x6d\xfb\xbd"
	"__fentry__\0\0"
	"\x1c\x00\x00\x00\xca\x39\x82\x5b"
	"__x86_return_thunk\0\0"
	"\x10\x00\x00\x00\x7e\x3a\x2c\x12"
	"_printk\0"
	"\x18\x00\x00\x00\x26\x0c\xae\x84"
	"module_layout\0\0\0"
	"\x00\x00\x00\x00\x00\x00\x00\x00";

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "8F2A7426321D8F81A6D1F55");

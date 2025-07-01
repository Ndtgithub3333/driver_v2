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
	"\x24\x00\x00\x00\x70\xce\x5c\xd3"
	"_raw_spin_unlock_irqrestore\0"
	"\x1c\x00\x00\x00\xcb\xf6\xfd\xf0"
	"__stack_chk_fail\0\0\0\0"
	"\x28\x00\x00\x00\xc4\xcd\x36\x4e"
	"__ubsan_handle_divrem_overflow\0\0"
	"\x2c\x00\x00\x00\xc6\xfa\xb1\x54"
	"__ubsan_handle_load_invalid_value\0\0\0"
	"\x10\x00\x00\x00\xa6\x50\xba\x15"
	"jiffies\0"
	"\x10\x00\x00\x00\xda\xfa\x66\x91"
	"strncpy\0"
	"\x10\x00\x00\x00\x7e\x3a\x2c\x12"
	"_printk\0"
	"\x10\x00\x00\x00\x11\x13\x92\x5a"
	"strncmp\0"
	"\x10\x00\x00\x00\xba\x0c\x7a\x03"
	"kfree\0\0\0"
	"\x14\x00\x00\x00\x30\xe1\x30\xba"
	"init_net\0\0\0\0"
	"\x20\x00\x00\x00\xa2\x46\xee\x06"
	"nf_unregister_net_hook\0\0"
	"\x14\x00\x00\x00\x63\xa4\xa3\xbd"
	"proc_remove\0"
	"\x20\x00\x00\x00\xe9\x0d\x1d\x44"
	"__kmalloc_large_noprof\0\0"
	"\x14\x00\x00\x00\xea\x3c\x40\x10"
	"proc_create\0"
	"\x20\x00\x00\x00\xdc\x3a\x28\x91"
	"nf_register_net_hook\0\0\0\0"
	"\x14\x00\x00\x00\x4c\xb8\x6a\xec"
	"seq_read\0\0\0\0"
	"\x14\x00\x00\x00\x1c\xc7\xf1\x3e"
	"seq_lseek\0\0\0"
	"\x18\x00\x00\x00\xc8\x4d\x99\x1f"
	"single_release\0\0"
	"\x14\x00\x00\x00\xbb\x6d\xfb\xbd"
	"__fentry__\0\0"
	"\x14\x00\x00\x00\x7f\x5c\x00\x0c"
	"single_open\0"
	"\x1c\x00\x00\x00\xca\x39\x82\x5b"
	"__x86_return_thunk\0\0"
	"\x14\x00\x00\x00\x3e\xe7\xce\x93"
	"seq_write\0\0\0"
	"\x14\x00\x00\x00\xb3\xf7\x12\x22"
	"seq_printf\0\0"
	"\x20\x00\x00\x00\x0b\x05\xdb\x34"
	"_raw_spin_lock_irqsave\0\0"
	"\x14\x00\x00\x00\x68\x99\x5a\x9e"
	"seq_putc\0\0\0\0"
	"\x14\x00\x00\x00\x6e\x4a\x6e\x65"
	"snprintf\0\0\0\0"
	"\x18\x00\x00\x00\x26\x0c\xae\x84"
	"module_layout\0\0\0"
	"\x00\x00\x00\x00\x00\x00\x00\x00";

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "AA6A9F19FFC73F06F8209EC");

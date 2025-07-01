# Thêm cờ debug
EXTRA_CFLAGS += -DDEBUG

obj-m := vnet_driver.o vnet_netfilter.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
        $(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

clean:
        $(MAKE) -C $(KDIR) M=$(PWD) clean
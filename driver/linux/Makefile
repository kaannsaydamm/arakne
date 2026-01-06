obj-m += arakne_probe.o
arakne_probe-objs := main.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	insmod arakne_probe.ko

uninstall:
	rmmod arakne_probe

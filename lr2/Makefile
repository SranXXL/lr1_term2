obj-m += lr2_term2.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test_module:
	-sudo rmmod lr2_term2
	-sudo rm /dev/lr2_term2
	sudo dmesg -C
	sudo insmod lr2_term2.ko
	sudo mknod /dev/lr2_term2 c 240 0
	sudo chmod 747 /dev/lr2_term2
	dmesg


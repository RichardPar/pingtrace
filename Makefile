obj-m += nf_out.o 
nf_out-y = nf.o 


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc superping.c -lpthread -o superping

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

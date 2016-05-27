obj-m += nf_out.o 
nf_out-y = nf.o 


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc newping.c -lpthread -o newping

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/signal.h>
#include <string.h>
#include <netdb.h>           // struct addrinfo
#include <sys/types.h>       // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>      // needed for socket()
#include <sys/ioctl.h>       // macro ioctl is defined
#include <bits/ioctls.h>     // defines values for argument "request" of ioctl.
#include <net/if.h>          // struct ifreq
#include <linux/if_ether.h>  // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <sys/time.h> // gettimeofday()
#include <ifaddrs.h>
#include <linux/if_link.h>



 
#define DEFDATALEN      56
#define MAXIPLEN        60
#define MAXICMPLEN      76

#define BUFSIZE         500
#define SERVICE_PORT    9090
 
 struct __attribute__((packed)) payload_t {
    char UID[6];
    char RUID[6];
    char MAC[6];
    char REQ;
    char DIR;
    char DEVICE[16];
};
 
struct timers_t {
  struct timeval  t1;
  struct timeval  t2;
  struct timeval  t3;
  
  struct timezone tz;
}; 
 
 
struct timers_t timers; 
 
static char *hostname = NULL;
pthread_t   udpthread;
char  cleanup;

void getRandomSequence(char *outSeq, int len); 
void printMacAddress(char *header, char *mac)
{
    int z;
    printf("%s ",header);
    for (z=0;z<6;z++)
      {
       printf("%2.2x",(unsigned char)mac[z]);
       if (z < 5)
           printf(":");
      }
}

void *udp_listen_function( void *ptr )
{
    
	struct sockaddr_in myaddr;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	int fd;				/* our socket */
	unsigned char buf[BUFSIZE];	/* receive buffer */
    double delta;

	/* create a UDP socket */

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket\n");
		return 0;
	}

	/* bind the socket to any valid IP address and a specific port */

	memset((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(SERVICE_PORT);

	if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		perror("bind failed");
		return 0;
	}

    printf("waiting on port %d\n", SERVICE_PORT);
	/* now loop, receiving data and printing what we received */
	for (;;) {
		recvlen = recvfrom(fd, buf, BUFSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
		//printf("received %d bytes\n", recvlen);
		if (recvlen > 0) {
			buf[recvlen] = 0;
			//printf("received message: \"%s\"\n", buf);
            (void) gettimeofday (&(timers.t3), &(timers.tz));
            delta = (double) (timers.t3.tv_sec - timers.t1.tv_sec) * 1000.0 + (double) (timers.t3.tv_usec - timers.t1.tv_usec) / 1000.0;
           
            struct payload_t *pl;
            pl = (struct payload_t *)buf;

            if (pl->REQ == 'P')
            {
                printf("PING ");
            } else
            {
                printf("RESP ");
            }

            if (pl->DIR == 'I')
            {
                printf("INGRESS ");
            } else
            {
                printf("EGRESS  ");
            }

            printMacAddress("",pl->UID);
            printMacAddress("",pl->RUID);
            printMacAddress("",pl->MAC);

            printf(" %s",pl->DEVICE);
            printf("\t%g ms",delta);    
            
            
            printf("\r\n");
            
		}
	}
	/* never exits */
} // Thread Func here..

 
static int in_cksum(unsigned short *buf, int sz)
{
  int nleft = sz;
  int sum = 0;
  unsigned short *w = buf;
  unsigned short ans = 0;
   
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
   
  if (nleft == 1) {
    *(unsigned char *) (&ans) = *(unsigned char *) w;
    sum += ans;
  }
   
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
   ans = ~sum;
   return (ans);
}
 
static void noresp(int ign)
{
  double delta;  
    
  if (cleanup == 0)
  {
     printf("No response from %s\n", hostname);
  } else
  {
       delta = (double) (timers.t2.tv_sec - timers.t1.tv_sec) * 1000.0 + (double) (timers.t2.tv_usec - timers.t1.tv_usec) / 1000.0;
           
      printf("%s %g ms is Alive\n", hostname,delta);
  }    
      
  exit(0);
}
 
static void ping(const char *host, unsigned short id, unsigned short seq)
{
  struct hostent *h;
  struct sockaddr_in pingaddr;
  struct icmp *pkt;
  int pingsock, c;
  char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
   
  if ((pingsock = socket(AF_INET, SOCK_RAW, 1)) < 0) {       /* 1 == ICMP */
    perror("ping: creating a raw socket");
    exit(1);
  }
   
  /* drop root privs if running setuid */
  setuid(getuid());
   
  memset(&pingaddr, 0, sizeof(struct sockaddr_in));
   
  pingaddr.sin_family = AF_INET;
  if (!(h = gethostbyname(host))) {
    fprintf(stderr, "ping: unknown host %s\n", host);
    exit(1);
  }
  memcpy(&pingaddr.sin_addr, h->h_addr, sizeof(pingaddr.sin_addr));
  hostname = h->h_name;
   
  pkt = (struct icmp *) packet;
  memset(pkt, 0, sizeof(packet));
  pkt->icmp_type = ICMP_ECHO;
  pkt->icmp_id = htons(id);
  pkt->icmp_seq = htons(seq);
  
  // Adding a Random 6 Byte random payload... so so that we can tell EGRESS
  char rnd[6];
  getRandomSequence(rnd,6);
  memcpy(packet+8,rnd,6);

  printMacAddress("Original Token->",rnd);
  printf("\r\n");  
  
  pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));
   
  c = sendto(pingsock, packet, sizeof(packet),0,(struct sockaddr *)&pingaddr, sizeof(struct sockaddr_in));
      // Start timer.
 (void) gettimeofday (&(timers.t1), &(timers.tz));
 
   
  if (c < 0 || c != sizeof(packet)) {
    if (c < 0)
      perror("ping: sendto");
    fprintf(stderr, "ping: write incomplete\n");
    exit(1);
  }
   
  signal(SIGALRM, noresp);
  alarm(5);                                     /* give the host 5000ms to respond */
  //pthread_join( udpthread, NULL);
  cleanup=0;
  /* listen for replies */
  while (1) {
    struct sockaddr from;
    int recvlen;
    
    socklen_t fromlen = sizeof(from);
     
    if ((c = recvfrom(pingsock,packet,sizeof(packet),0,(struct sockaddr *)&from,&fromlen)) < 0) {
      if (errno == EINTR)
        continue;
      perror("ping: recvfrom");
      continue;
    }
    if (c >= 76) {                   /* ip + icmp */
      struct iphdr *iphdr = (struct iphdr *) packet;
       
      pkt = (struct icmp *) (packet + (iphdr->ihl << 2));      /* skip ip hdr */
      if (pkt->icmp_type == ICMP_ECHOREPLY)
      {
          (void) gettimeofday (&(timers.t2), &(timers.tz));
          cleanup=1;
          alarm(1); // 1 second more just to make sure all UDP have arrived
      }
        
    }
  }
  return;
}
 
void getRandomSequence(char *outSeq, int len)
{
  int byte_count = 64;
  char data[64];
  FILE *fp;
  fp = fopen("/dev/urandom", "r");
  fread(outSeq, 1, len, fp);
  fclose(fp);
} 
 
int main (int argc, char *argv[])
{
  if (argc != 2)
  {
      printf("Eyee! not enought information here! please supply an IP address\r\n");
      exit(0);
  }  

  pthread_create( &udpthread, NULL, udp_listen_function,NULL);
    
  ping (argv[1],getpid(),0);
 
}

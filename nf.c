
#ifndef __KERNEL__
#define __KERNEL__
#endif
#ifndef MODULE
#define MODULE
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <net/dst.h>
#include <net/arp.h>

//#include <linux/neighbour.h>

#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>

#define SPORT 65210
#define DPORT 9090

struct __attribute__((packed)) payload_t {
    char UID[6];
    char RUID[6];
    char MAC[6];
    char REQ;
    char DIR;
    char DEVICE[16];
};


struct net_device* bridge_dev;
char* bridgeDevice = "br0";

module_param(bridgeDevice, charp, 0000);
MODULE_PARM_DESC(bridgeDevice, "Name of the Ethernet Bridge [br0 is default]");

char G_UID[6];

unsigned short in_cksum(unsigned short* addr, int len);
struct net_device *isDeviceinBridge(const struct net_device* nd);

static void send_packet_skb(char* srcMac,
                            char* destMac,
                            u32 srcIp,
                            u32 destIp,
                            const struct net_device* device,
                            char* data,
                            int len);

unsigned int nf_icmp_forward_hook(unsigned int hooknum,
                                  struct sk_buff* skb,
                                  const struct net_device* in,
                                  const struct net_device* out,
                                  int (*okfn)(struct sk_buff*));

unsigned int nf_icmp_postrouting_hook(unsigned int hooknum,
                                      struct sk_buff* skb,
                                      const struct net_device* in,
                                      const struct net_device* out,
                                      int (*okfn)(struct sk_buff*));

static struct nf_hook_ops nf_customtrace_ops[] __read_mostly = { { .hook = (nf_hookfn*)nf_icmp_forward_hook,
                                                                   .owner = THIS_MODULE,
                                                                   .pf = NFPROTO_BRIDGE,
                                                                   .hooknum = NF_BR_FORWARD,
                                                                   .priority = NF_BR_PRI_FILTER_BRIDGED, },
                                                                 { .hook = (nf_hookfn*)nf_icmp_postrouting_hook,
                                                                   .owner = THIS_MODULE,
                                                                   .pf = NFPROTO_BRIDGE,
                                                                   .hooknum = NF_BR_POST_ROUTING,
                                                                   .priority = NF_BR_PRI_LAST, }, };

unsigned int nf_icmp_postrouting_hook(unsigned int hooknum,
                                      struct sk_buff* skb,
                                      const struct net_device* in,
                                      const struct net_device* out,
                                      int (*okfn)(struct sk_buff*))
{
    struct ethhdr* eth_header;
    struct iphdr* ip_header;
    struct icmphdr* icmp_header;
    char   IN_UID[6];

    if (skb) {

        eth_header = (struct ethhdr*)(skb_mac_header(skb));
        ip_header = (struct iphdr*)(skb_network_header(skb));

        /* caculate checksum */

        if (ip_header->protocol == IPPROTO_ICMP) {
            struct net_device* i;
            icmp_header = (struct icmphdr*)(skb->data + sizeof(struct iphdr));

            if (skb->len != 212)
            {
                // This is not my packet to tinker with!
                return NF_ACCEPT;
            }

            bridge_dev = isDeviceinBridge(out); 
            if (bridge_dev == NULL)
            {
                printk("EGRESS not part of the  %s Bridge (ignoring packet)\r\n",bridgeDevice);
                return NF_ACCEPT;
            }

            char *payload = (char *)(skb->data + sizeof(struct iphdr) + sizeof(struct icmphdr));
            memcpy(IN_UID,payload,6);
            

            i = dev_get_by_index_rcu(&init_net, skb->skb_iif);
            printk("Got ICMP INGRESS on %s [Type=0x%2.2x] [%x:%x:%x:%x:%x:%x] [%d]\r\n",
                   i->name,
                   icmp_header->type,
                   out->dev_addr[0],
                   out->dev_addr[1],
                   out->dev_addr[2],
                   out->dev_addr[3],
                   out->dev_addr[4],
                   out->dev_addr[5],
                   skb->skb_iif);

            if (icmp_header->type == 0x08) {
                u32 sip;
                u32 dip;
                struct payload_t outPacket;

                sip = ip_header->saddr;
                dip = ip_header->daddr;

                memcpy(&outPacket.UID, G_UID, 6);
                memcpy(&outPacket.RUID, IN_UID, 6);
                memcpy(&outPacket.MAC,out->dev_addr, 6);
                strncpy(outPacket.DEVICE, out->name, 16);
                outPacket.REQ = 'P';
                outPacket.DIR = 'E';

                send_packet_skb(eth_header->h_dest, eth_header->h_source, dip, sip, bridge_dev, (char *)&outPacket, sizeof(struct payload_t));

            } else if (icmp_header->type == 0x00) {

                u32 sip;
                u32 dip;
                struct payload_t outPacket;

                sip = ip_header->saddr;
                dip = ip_header->daddr;

                memcpy(&outPacket.UID, G_UID, 6);
                memcpy(&outPacket.RUID, IN_UID, 6);
                memcpy(&outPacket.MAC,out->dev_addr, 6);
                strncpy(outPacket.DEVICE, out->name, 16);
                outPacket.REQ = 'R';
                outPacket.DIR = 'E';

                send_packet_skb(eth_header->h_source, eth_header->h_dest, sip, dip, bridge_dev, (char *)&outPacket, sizeof(struct payload_t));
            }
        }
    }

    return NF_ACCEPT;
}
unsigned int nf_icmp_forward_hook(unsigned int hooknum,
                                  struct sk_buff* skb,
                                  const struct net_device* in,
                                  const struct net_device* out,
                                  int (*okfn)(struct sk_buff*))
{

    struct ethhdr* eth_header;
    struct iphdr* ip_header;
    struct icmphdr* icmp_header;
    char IN_UID[6];
    char OUT_UID[6];

    if (skb) {

        eth_header = (struct ethhdr*)(skb_mac_header(skb));
        ip_header = (struct iphdr*)(skb_network_header(skb));

        if (ip_header->protocol == IPPROTO_ICMP) {
            struct net_device* i;
            
            if (skb->len != 212)
            {
                // This is not my magic packet!
                return NF_ACCEPT;
            }

            bridge_dev = isDeviceinBridge(in); 
            if (bridge_dev == NULL)
            {
                printk("INGRESS not part of the  %s Bridge (ignoring packet)\r\n",bridgeDevice);
                return NF_ACCEPT;
            }

            icmp_header = (struct icmphdr*)(skb->data + sizeof(struct iphdr));

            char *payload = (char *)(skb->data + sizeof(struct iphdr) + sizeof(struct icmphdr));
            memcpy(IN_UID,payload,6);
            print_hex_dump(KERN_DEBUG,"IN_UID->", DUMP_PREFIX_NONE, 16, 1, IN_UID,6,false);
            get_random_bytes(OUT_UID, 6);
            memcpy(payload,OUT_UID,6);

            ip_header->check = 0; // <------------ verrrrrrrrrrry important
            ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);

            icmp_header->checksum = 0;
            icmp_header->checksum =
            in_cksum((unsigned short*)icmp_header, ntohs(ip_header->tot_len) - (ip_header->ihl << 2));

            skb->csum = 0; // <------------ verrrrrrrrrrry important
            skb->csum = skb_checksum(skb, ip_header->ihl * 4, skb->len - ip_header->ihl * 4, 0);

            i = dev_get_by_index_rcu(&init_net, skb->skb_iif);
            printk("Got ICMP EGRESS on %s [Type=0x%2.2x] [%x:%x:%x:%x:%x:%x] [%d]\r\n",
                   i->name,
                   icmp_header->type,
                   in->dev_addr[0],
                   in->dev_addr[1],
                   in->dev_addr[2],
                   in->dev_addr[3],
                   in->dev_addr[4],
                   in->dev_addr[5],
                   skb->skb_iif);
            
            
            if (icmp_header->type == 0x08) {
                u32 sip;
                u32 dip;
                struct payload_t outPacket;

                sip = ip_header->saddr;
                dip = ip_header->daddr;

                memcpy(&outPacket.UID, G_UID, 6);
                memcpy(&outPacket.RUID, IN_UID, 6);
                memcpy(&outPacket.MAC,in->dev_addr, 6);
                strncpy(outPacket.DEVICE, in->name, 16);
                outPacket.REQ = 'P';
                outPacket.DIR = 'I';
                
                send_packet_skb(eth_header->h_dest, eth_header->h_source, dip, sip, bridge_dev, (char *)&outPacket, sizeof(struct payload_t));

            } else if (icmp_header->type == 0x00) {

                u32 sip;
                u32 dip;
                struct payload_t outPacket;

                sip = ip_header->saddr;
                dip = ip_header->daddr;

                memcpy(&outPacket.UID, G_UID, 6);
                memcpy(&outPacket.RUID, IN_UID, 6);
                memcpy(&outPacket.MAC,in->dev_addr, 6);
                strncpy(outPacket.DEVICE, in->name, 16);
                outPacket.REQ = 'R';
                outPacket.DIR = 'I';
                
                send_packet_skb(eth_header->h_source, eth_header->h_dest, sip, dip, bridge_dev, (char *)&outPacket, sizeof(struct payload_t));
            }
        }
    }
    return NF_ACCEPT;
}

static void send_packet_skb(char* srcMac,
                            char* destMac,
                            u32 srcIp,
                            u32 destIp,
                            const struct net_device* device,
                            char* data,
                            int len)
{
    struct ethhdr* eth_header = NULL;
    struct iphdr* ip_header = NULL;
    struct udphdr* udp_header = NULL;
    struct sk_buff* skb = NULL;
    unsigned short ident;

    u32 skb_len;
    u8* pdata = NULL;
    u32 data_len = len;

    skb_len = data_len + sizeof(struct iphdr) + sizeof(struct udphdr) + LL_RESERVED_SPACE(device);
    skb = dev_alloc_skb(skb_len);
    // skb = alloc_skb(skb_len, GFP_ATOMIC);
    if (!skb) {
        return;
    }
    skb_reserve(skb, LL_RESERVED_SPACE(device));

    skb->dev = (struct net_device*)device;
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    skb_set_network_header(skb, 0);
    skb_put(skb, sizeof(struct iphdr));
    skb_set_transport_header(skb, sizeof(struct iphdr));
    skb_put(skb, sizeof(struct udphdr));
    /* construct udp header in skb */
    udp_header = udp_hdr(skb);
    udp_header->source = htons(SPORT);
    udp_header->dest = htons(DPORT);
    udp_header->check = 0;


    /* construct ip header in skb */
    ip_header = ip_hdr(skb);
    ip_header->version = 4;
    ip_header->ihl = sizeof(struct iphdr) >> 2;

    ip_header->frag_off = 0;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->tos = 0;

    get_random_bytes(&ident, 2);
    
    ip_header->id = htons(ident);
    ip_header->daddr = destIp;
    ip_header->saddr = srcIp;
    ip_header->ttl = 0x40;
    ip_header->tot_len = htons(skb_len-32);
    ip_header->check = 0;

    /* caculate checksum */
    ip_header->check=0;
    ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);

    udp_header->len = htons(len + sizeof(struct udphdr));
    udp_header->check = 0;
    //udp_header->check = htons(in_cksum((unsigned short *) udp_header, len + sizeof(struct udphdr)));
    //udp_header->check = csum_tcpudp_magic(srcIp, destIp, skb->len - ip_header->ihl * 4, IPPROTO_UDP, skb->csum);

    skb->csum = 0;
    skb->csum = skb_checksum(skb, ip_header->ihl * 4, skb->len - ip_header->ihl * 4, 0);
    

    /* insert data in skb */
    pdata = skb_put(skb, len);
    if (pdata) {
        memcpy(pdata, data, len);
    }

    /* construct ethernet header in skb */
    eth_header = (struct ethhdr*)skb_push(skb, 14);
    memcpy(eth_header->h_dest, destMac, ETH_ALEN);
    memcpy(eth_header->h_source, srcMac, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_IP);

    /* send packet */
    if (dev_queue_xmit(skb) < 0) {
        dev_put((struct net_device*)device);
        kfree_skb(skb);
        printk("send packet by skb failed.\n");
        return;
    }
    return;
}

struct net_device *isDeviceinBridge(const struct net_device* nd)
{
    struct net_device *br_master;

    rtnl_lock();
    br_master = netdev_master_upper_dev_get((struct net_device *)nd);
    rtnl_unlock();
    
    if (br_master==NULL)
    {
        printk("Eeeeeeeek! this should not happen! Interface %s is not in a bridge\r\n",nd->name);
        return NULL;
    }
    if (strncmp(br_master->name,bridgeDevice,16))
    {
        printk("Not in the interested Bridge\r\n");
        return NULL;
    }
    
    return br_master;
}

unsigned short in_cksum(unsigned short* addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short* w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

int init_module() 
{
    int ret;
    // struct net_device* dev;

    get_random_bytes(G_UID, 6);
    
    bridge_dev = dev_get_by_name(&init_net, bridgeDevice);
    printk("NetFilter Bridge Trace loading on interface %s\r\n", bridgeDevice);
    print_hex_dump(KERN_DEBUG,"G_UID->", DUMP_PREFIX_NONE, 16, 1, G_UID,6,false);

    if (bridge_dev == NULL) {
        printk("Bridge %s seems to be non-existent! .. Burnt?\r\n", bridgeDevice);
        return -1;
    }

#if 0   
    // This is here as an example ..
    read_lock(&dev_base_lock);
    dev = first_net_device(&init_net);
    while (dev) {
        printk(KERN_INFO "found [%s]\n", dev->name);
        if (!strcmp(dev->name,bridgeDevice))
        {
            printk("Using Bridge %s\r\n",dev->name);
            bridge_dev=dev;
        }
        dev = next_net_device(dev);
    }
    read_unlock(&dev_base_lock);
#endif

    ret = nf_register_hooks(nf_customtrace_ops, ARRAY_SIZE(nf_customtrace_ops));
    if (ret < 0) {
        printk("register nf hook fail\n");
        return ret;
    }
    printk(KERN_NOTICE "register nf customtrace hook\n");
    return 0;
}

void cleanup_module()
{
    nf_unregister_hooks(nf_customtrace_ops, ARRAY_SIZE(nf_customtrace_ops));
}

MODULE_LICENSE("GPL");
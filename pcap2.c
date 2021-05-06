#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include<netinet/if_ether.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include<netinet/tcp.h>
//#include<pcap.h>
//#include"headers.h"
//#include<sys/types.h>
//#include<netinet/in.h>
void handler(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes)
{
	int k;
	static int i=1;
	struct ether_header *eth=bytes;
	struct ip *inet=bytes+sizeof(struct ether_header);
	struct tcphdr *tc=bytes+sizeof(struct ether_header)+(inet->ip_hl);
	printf("\n-->PACKET %d\n",i++);
	printf("Source MAC address: ");
	for(k=0;k<ETH_ALEN;k++)
	{
		printf("%x: ",eth->ether_shost[k]);
	}
	printf("\nDestination MAC address: ");
	for(k=0;k<ETH_ALEN;k++)
	{
		printf("%x: ",eth->ether_dhost[k]);
	}
	//if(ntohs(eth->ether_type)==ETHERTYPE_IP)//ethernet.h
	//{
	printf("\nID: %d\n",eth->ether_type);
	printf("header length %d\n",inet->ip_hl);
	printf("version :%d\n",inet-> ip_v);
	printf("type of service %d\n",inet->ip_tos); 
	printf("total length %d\n",inet-> ip_len);
	printf("identification %d\n",inet->ip_id);
	//printf("reserved fragment flag %d\n",IP_RF);
	//printf("dont fragment flag %d\n",IP_DF);
	//printf("more fragment flag %d\n",IP_MF);
	printf("fragment offset field %d\n",inet->ip_off);
	printf("time to live %d\n",inet->ip_ttl);
	printf("protocol %d\n",inet->ip_p);
	if(IPPROTO_TCP==inet->ip_p)//usr->include->netinet->in.h
		printf("TCP\n");
	if(IPPROTO_UDP==inet->ip_p)//usr->include->netinet->in.h
		printf("UDP\n");
	printf("IP dest address: %s \n",inet_ntoa(inet->ip_dst));
	printf("IP src address:  %s\n",inet_ntoa(inet->ip_src));
	printf("source port no. %d\n",ntohs(tc->source));//usr->include->netinet->tcp.h
	printf("destination port no. %d\n",ntohs(tc->dest));//usr->include->netinet->tcp.h
	printf("checksum %d\n",inet->ip_sum);
	//}
}
int main()
{
	//char *dev; /* name of the device to use */
	char *net; /* dot notation of the network address */
	char *mask;/* dot notation of the network mask*/
	int ret;/* return code */
	//char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp; /* ip*/
	bpf_u_int32 maskp;/* subnet mask */
	struct in_addr addr;


	pcap_if_t *head=NULL,*curr;
	char err[255];
	pcap_t *device=NULL;
	if(pcap_findalldevs(&head,err))
	{
		printf("Unable to open\n");
		return;
	}
	curr=head;
	while(curr!=NULL)
	{
		printf("Name:%s\n",curr->name);
		curr=curr->next;
	}
	if(!(device=pcap_open_live("usb0",1024,0,10000,err)))
	{
		printf("Unable to open\n");
		return;
	}
	pcap_loop(device,50,handler,NULL);


	printf("\n");
	/* ask pcap for the network address and mask of the device */
	ret = pcap_lookupnet("usb0",&netp,&maskp,err);//NULL);//errbuf);
	if(ret == -1)
	{
		printf("errbuf\n");
		exit(1);
	}
	/* get the network address in a human readable form */
	addr.s_addr = netp;
	net = inet_ntoa(addr);
	if(net == NULL)/* thanks Scott :-P */
	{
		perror("inet_ntoa");
		exit(1);
	}
	printf("NET: %s\n",net);
	/* do the same as above for the device's mask */
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL)
	{
		perror("inet_ntoa");
		exit(1);
	}
	printf("MASK: %s\n",mask);
	return 0;
}

	/* ask pcap for the network address and mask of the device */
	/*ret = pcap_lookupnet("eth1",&netp,&maskp,NULL);//errbuf);
	if(ret == -1)
	{
		printf("errbuf\n");
		exit(1);
	}
	/* get the network address in a human readable form */
	/*addr.s_addr = netp;
	net = inet_ntoa(addr);
	if(net == NULL)/* thanks Scott :-P */
	/*{
	perror("inet_ntoa");
	exit(1);
	}*/
	

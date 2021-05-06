#include<pcap/pcap.h>
int main()
{
	pcap_if_t *head=NULL,*curr;
	char err[255];
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
}

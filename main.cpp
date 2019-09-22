#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

struct ethernet {
  unsigned char src_ip[6];
  unsigned char dst_ip[6];
  unsigned short type;
};

struct ip {
 unsigned char header_length:4;
 unsigned char version:4;
 unsigned char service_field;
 unsigned short total_length;
};

struct tcp {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int sequence_number;
	unsigned int acknowledgement_number;
	unsigned char a:1;
	unsigned char b:3;
	unsigned char tcp_length:4;
	unsigned char data;
	unsigned short window_size;
	unsigned short checksum;
	unsigned short urgent_pointer;

};

void print_ethernet(const unsigned char *data){
	printf("\n---------------------------Ethernet---------------------------------\n");
  struct ethernet *ethernet;
  ethernet = (struct ethernet *)data;
  printf("src ip : ");
  for(int i=0;i<=5;i++){
    printf("%02x ",ethernet->src_ip[i]);
  }
  printf("\ndst ip :");
   for(int i=0;i<=5;i++){
    printf("%02x ",ethernet->dst_ip[i]);
  };printf("\n");
   const unsigned short type = ntohs(ethernet->type);
   if(type==0x0800)
	   printf("Type: IPv4 0x0800\n");
}

int print_ip(const unsigned char *data){
	printf("--------------------------------IP--------------------------------\n");
   	struct ip *ip;
	ip = (struct ip *)data;
	
	int len = ((int)ip->header_length*(int)ip->version);
	printf("header length: %d bytes\n",len);
	printf("total length : %d\n",(int)ntohs(ip->total_length));
	data+=len-8;
	const unsigned char *src_ip = (const unsigned char*)data;
	data+=4;
	const unsigned char *dst_ip = (const unsigned char*)data;
	printf("src ip : %d.%d.%d.%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
	printf("dst ip : %d.%d.%d.%d\n",dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3]);
	data+=4;
	return len;
}

int print_TCP(const unsigned char *data){
	printf("--------------------------------TCP---------------------------------\n");
	struct tcp *tcp;
	tcp = (struct tcp*)data;
	printf("src port : %d\n",ntohs(tcp->src_port),tcp->src_port);
	printf("dst port : %d\n",ntohs(tcp->dst_port));
	return (int)(tcp->tcp_length)*4;
}

void print_data(const unsigned char *data){
	printf("----------------------------------DATA---------------------------------\n");
	printf("%s\n",data);
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n\n\n\n\n\n");
    printf("------------------------------------------start------------------------------\n");
    printf("%u bytes captured\n", header->caplen);
	print_ethernet(packet);
	packet+=14;
	int len = print_ip(packet);
	packet+=len;
	len =print_TCP(packet);
	packet+=len;
	print_data(packet);;
  }

  pcap_close(handle);
  return 0;
}

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

struct ethernet {
  unsigned char src_ip[6];
  unsigned char dst_ip[6];
  unsigned short type;
};

struct ip {
 unsigned char version;
 unsigned char service_field;
 unsigned short total_length;
};

void print_ethernet(const unsigned char *data){
	printf("Ethernet---------------------------------\n");
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

void print_ip(const unsigned char *data){
	printf("IP------------------------------\n");
	printf("%100x\n",*data);
	printf("\n");
   	struct ip *ip;
	ip = (struct ip *)data;
	printf("version %02x service field %02x\n",ip->version,ip->service_field);
	printf("total length: %d 0x:%04x\n",ntohs(ip->total_length),ip->total_length);
	int len = (int)ntohs(ip->total_length);
	data+=len-8;
	const unsigned char *src_ip = (const unsigned char*)data;
	data+=4;
	const unsigned char *dst_ip = (const unsigned char*)data;
	printf("src ip : %d.%d.%d.%d\n",src_ip[0],src_ip[1],src_ip[2],src_ip[3]);
}

void print_TCP(const unsigned char *data){
	printf("TCP--------------------------------\n");
	const unsigned short src_port = *(const unsigned short*)data;
	data+=2;
	const unsigned short dst_port = *(const unsigned short*)data;
	data+=10;
	const unsigned char length = *(const unsigned char*)data;
	data+=length-12;
	printf("src_port : %x\n",ntohs(src_port));
	printf("dst_port: %x\n",ntohs(dst_port));
}

void print_data(const unsigned char *data){
	printf("DATA---------------------------------\n");
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
    printf("%u bytes captured\n", header->caplen);
	print_ethernet(packet);
	packet+=14;
	print_ip(packet);
	print_TCP(packet);
	print_data(packet);;
  }

  pcap_close(handle);
  return 0;
}

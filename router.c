// Patrascoiu Ion - Radu, 322 CD

#include "skel.h"
#include "queue.h"
#define ARP_REQUEST_CODE 1 
#define ARP_REPLY_CODE 2
#define ICMP_OFF 34

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

struct arp_header {
    uint16_t htype;        //hardware type
    uint16_t ptype;        //protocol type
    uint8_t hlen;          //hardware length
    uint8_t plen;          //protocol length
    uint16_t opcode;       //operation code - 1 for request, 2 for reply
    uint8_t sender_mac[6];  //source hardware address
    uint8_t sender_ip[4];        //source protocol address
    uint8_t target_mac[6];  //destination hardware address
    uint8_t target_ip[4];        //destination protocol address
};

struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_size;

uint16_t ip_checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;
	uint64_t acc=0xffff;

	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	return htons(~acc);
}

void parse_route_table() {
	FILE *f = fopen("rtable.txt", "r");
	char line[50];
	int i = 0;
	for(i = 0; fgets(line, sizeof(line), f); i++) {
		char prefix[20], next_hop[20], mask[20], interface[20];
		sscanf(line, "%s %s %s %s", prefix, next_hop, mask, interface);
		rtable[i].prefix = inet_addr(prefix);
		rtable[i].next_hop = inet_addr(next_hop);
		rtable[i].mask = inet_addr(mask);
		rtable[i].interface = atoi(interface);
	}

	rtable_size = i;
	fclose(f);
}

void add_arp_table(uint8_t *ip, uint8_t *mac){	
	memcpy(&arp_table[arp_table_size].ip, ip, 4 * sizeof(uint8_t));
    memcpy(&arp_table[arp_table_size].mac, mac, 6 * sizeof(uint8_t));
    arp_table_size++;
}

struct route_table_entry *get_best_route(__u32 dest_ip) {	
	int position = -1;

	for(int i = 0; i < rtable_size; ++i) {
		int check_prefix = rtable[i].mask & dest_ip;
		if(check_prefix == rtable[i].prefix) {
			if(rtable[position].mask <= rtable[i].mask) {
				position = i;
			}
		}
	}

	if(position == -1) {
		return NULL;
	}

	return &rtable[position];
}

struct arp_entry *query_arp_table(uint32_t ip) {
    int position = -1;
    
    for (int i = 0; i < arp_table_size; ++i) {
		if (memcmp(&arp_table[i].ip, &ip, 4) == 0){
			position = i;
			break;
		}
    }

	if(position == -1) {
		return NULL;
	}
    
    return &arp_table[position];
}

// functie pentru tiemout si host unreachable
void imcp_function(packet m, int type_number) {

		// extrag headerele din pachetul vechi
		struct ether_header *ethhdr = (struct ether_header*)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof (struct ether_header));

		// formez un nou pachet
		packet host_unreachable_packet;
		struct ether_header *ethhdr_hu = (struct ether_header*)host_unreachable_packet.payload;
		struct iphdr *ip_hdr_hu = (struct iphdr *)(host_unreachable_packet.payload + sizeof (struct ether_header));
		struct icmphdr *icmp_hdr_hu = (struct icmphdr *)(host_unreachable_packet.payload + ICMP_OFF);	

		host_unreachable_packet.interface = m.interface;
		host_unreachable_packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

		ethhdr_hu->ether_type = htons(ETHERTYPE_IP);
		memcpy(ethhdr_hu->ether_dhost, ethhdr->ether_shost, 6 * sizeof (uint8_t));
		get_interface_mac(m.interface, ethhdr_hu->ether_shost);
		
		ip_hdr_hu->version = 4;
		ip_hdr_hu->ihl = 5;
		ip_hdr_hu->ttl = 64;
		ip_hdr_hu->protocol = IPPROTO_ICMP;
		ip_hdr_hu->id = htons(getpid() & 0xFFFF);
		ip_hdr_hu->daddr = ip_hdr->saddr;
		ip_hdr_hu->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);


		struct in_addr router_addr;
		char *aux = get_interface_ip(m.interface);
		inet_aton(aux, &router_addr);

		memcpy(&ip_hdr_hu->saddr, &router_addr, 4 * sizeof(struct iphdr));

		ip_hdr_hu->check = 0;
		ip_hdr_hu->check = ip_checksum(ip_hdr_hu, sizeof(struct iphdr));

		icmp_hdr_hu->code = 0;
		icmp_hdr_hu->type = type_number;
		icmp_hdr_hu->un.echo.id = htons(getpid() & 0xFFFF);
		icmp_hdr_hu->un.echo.sequence = 0;
		icmp_hdr_hu->checksum = 0;
		icmp_hdr_hu->checksum = ip_checksum(icmp_hdr_hu, sizeof(struct icmphdr));

		send_packet(host_unreachable_packet.interface, &host_unreachable_packet);
}

int main(int argc, char *argv[]) {
	packet m;
	int rc;

	init();
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	arp_table = calloc(10, sizeof(struct  arp_entry));
	arp_table_size = 0;
	parse_route_table();

	// creez coada
	queue q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		// scot pachetul ethernet din pachet
		struct ether_header *ethhdr = (struct ether_header*)m.payload;

	 	 // daca e pachet ARP
		if (ntohs(ethhdr->ether_type) == ETHERTYPE_ARP) {

			// scot pachetul arp din pachet
			struct arp_header *arphdr = (struct arp_header*) (m.payload + sizeof(struct ether_header));

			// daca este ARP REQUEST
			if (ntohs(arphdr->opcode) == ARP_REQUEST_CODE) {

				struct in_addr my_address;
				char *my_ip = get_interface_ip(m.interface);
				inet_aton(my_ip, &my_address);

				// verific daca este un request destinat mie
				if (memcmp(&my_address, arphdr->target_ip, 4) == 0) {
					ethhdr->ether_type = htons(ETHERTYPE_ARP); // tipul
					memcpy(ethhdr->ether_dhost, ethhdr->ether_shost, 6 * sizeof (uint8_t)); // adresa MAC destinatie
					get_interface_mac(m.interface, ethhdr->ether_shost);

					arphdr->htype = htons(1); // 1 pentru ethernet
					arphdr->ptype = htons(ETH_P_IP); // 2048 pentru IP
					arphdr->hlen = 6; // 6 bytes pentru adresa MAC
					arphdr->plen = 4; // 4 bytes pentru adresa IPv4
					arphdr->opcode = htons(ARP_REPLY_CODE); // 1 pentru REQUEST, 2 PENTRU REPLY

					// se schimba adresele de mac si ip
					memcpy(arphdr->target_ip, arphdr->sender_ip, 4 * sizeof (uint8_t));
					inet_pton(AF_INET, get_interface_ip(m.interface), arphdr->sender_ip);
					memcpy(arphdr->target_mac, arphdr->sender_mac, 6 * sizeof (uint8_t));
					get_interface_mac(m.interface, arphdr->sender_mac);

					send_packet(m.interface, &m);
				}
				
			// daca este ARP REPLY
			} else if(ntohs(arphdr->opcode) == ARP_REPLY_CODE) {
				
				// actualizez tabela arp
				add_arp_table(arphdr->sender_ip, arphdr->sender_mac);

				// golesc coada
				while(!queue_empty(q)) {
					packet *reply_packet = queue_deq(q);

					struct ether_header *ethhdr_reply = (struct ether_header*)reply_packet->payload;
					struct iphdr *ip_hdr_reply = (struct iphdr *)(reply_packet->payload + sizeof (struct ether_header));

					struct route_table_entry *reply_entry = get_best_route(ip_hdr_reply->daddr);
					memcpy(&ethhdr_reply->ether_dhost, &ethhdr->ether_shost, 6 * sizeof (uint8_t));

					// trimit pachetul pe interfata potrivita
					send_packet(reply_entry->interface, reply_packet);
				}
			}
			// daca e pachet IP
		} else if(ntohs(ethhdr->ether_type) == ETHERTYPE_IP){
			
			// extra headerul ip
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof (struct ether_header));

			// daca este pachet ICMP
			if(ip_hdr->protocol == IPPROTO_ICMP) {

				// extra headerul icmp
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);
				struct in_addr router_addr;
				char *aux = get_interface_ip(m.interface);
				inet_aton(aux, &router_addr);
				
				// verific daca este un icmp echo request destinat mie
				if(icmp_hdr->type == ICMP_ECHO && memcmp(&ip_hdr->daddr, &router_addr.s_addr, 4 * sizeof(uint8_t)) == 0) {

					memcpy(&ip_hdr->daddr, &ip_hdr->saddr, 4 * sizeof(uint8_t));
					memcpy(&ip_hdr->saddr, &router_addr, 4 * sizeof(uint8_t));

					ip_hdr->check = 0;
					ip_hdr->check = htons(ip_checksum(ip_hdr, sizeof(struct iphdr)));

					icmp_hdr->type = 0; // ECHO REPLY;
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

					send_packet(m.interface, &m);
				}
			}

			__u16 check_sum = ip_hdr->check;
			ip_hdr->check = 0;
			// arunc pachetul corupt
			if(check_sum != ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			}

			if(ip_hdr->ttl > 1) {
			
				packet toBeSent;
				struct ether_header *ethhdr_to_send = (struct ether_header*)toBeSent.payload;
				struct arp_header *arphdr_to_send = (struct arp_header*) (toBeSent.payload + sizeof(struct ether_header));

				struct route_table_entry *my_entry = get_best_route(ip_hdr->daddr);

				// daca am gasit o ruta viabila
				if(my_entry != NULL) {

					ip_hdr->ttl -= 1;
					ip_hdr->check = 0;
					ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

					// daca nu se stie adresa MAC, adica nu se gaseste in tabela arp
					if(query_arp_table(ip_hdr->daddr) == NULL) {

							packet temp;
							temp.len = m.len;
							temp.interface = m.interface;
							memcpy(temp.payload, m.payload, sizeof(struct ether_header) + sizeof(struct iphdr));

							// adaug o copie a pachetului in coada
							queue_enq(q, &temp);

							toBeSent.interface = my_entry->interface;
							toBeSent.len = sizeof(struct ether_header) + sizeof(struct arp_header);

							memset(ethhdr_to_send->ether_dhost, 0xff, 6 * sizeof (uint8_t)); // broadcast
							get_interface_mac(toBeSent.interface, ethhdr_to_send->ether_shost);
							ethhdr_to_send->ether_type = htons(ETHERTYPE_ARP); // tipul

							arphdr_to_send->htype = htons(1); // 1 pentru ethernet
							arphdr_to_send->ptype = htons(ETH_P_IP); // 2048 pentru IP
							arphdr_to_send->hlen = 6; // 6 bytes pentru adresa MAC
							arphdr_to_send->plen = 4; // 4 bytes pentru adresa IPv4
							arphdr_to_send->opcode = htons(ARP_REQUEST_CODE); // 1 pentru REQUEST, 2 PENTRU REPLY

							memcpy(&arphdr_to_send->target_ip, &ip_hdr->daddr, 4 * sizeof (uint8_t));											
							
							struct in_addr my_address;
							char *my_ip = get_interface_ip(toBeSent.interface);
							inet_aton(my_ip, &my_address);
							memcpy(&arphdr_to_send->sender_ip, &my_address,  4 * sizeof (uint8_t));

							memset(&arphdr_to_send->target_mac, 0, 6 * sizeof (uint8_t));
							get_interface_mac(toBeSent.interface, arphdr_to_send->sender_mac);

							if(my_entry != NULL) {
								send_packet(toBeSent.interface, &toBeSent);
							}
							
						// adresa MAC se afla in table ARP
					} else {
						struct arp_entry *arp_entry = query_arp_table(ip_hdr->daddr);

						memcpy(&ethhdr->ether_dhost, &arp_entry->mac, 6 * sizeof(uint8_t));
						send_packet(my_entry->interface, &m);
					}

				} else {
					// imcp host_unreachable
					imcp_function(m, 3);
				}

			} else {
				// icmp_timeout(time exceeded)
				imcp_function(m, 11);
			}
		}
	}
}
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include "./include/queue.h"
#include "./include/lib.h"
#include "./include/protocols.h"

//structure to store a packet while its waiting in the queue for an ARP replay
struct packet {
	char buf[MAX_PACKET_LEN];
	size_t len;
	struct route_table_entry r;
};

//the queue that stores the waiting packets
queue q;

struct route_table_entry *rtable;
int rtable_len;

//helper function for radix sort that performs a counting sort on a specific byte of the mask
void cmp_mask(struct route_table_entry *arr, struct route_table_entry *output, int n, int shift) {
    int count[256];
    memset(count, 0, sizeof(count));

    //count each byte appereace
    for (int i = 0; i < n; i++) {
        uint32_t val = ntohl(arr[i].mask);
        int byte = (val >> shift) & 0xff;
        count[byte]++;
    }

    //add counts to find possition
    for (int i = 1; i < 256; i++) {
        count[i] += count[i - 1];
    }

    //build the output array backwards to maintain sorting stability
    for (int i = n - 1; i >= 0; i--) {
        uint32_t val = ntohl(arr[i].mask);
        int byte = (val >> shift) & 0xff;
        output[count[byte] - 1] = arr[i];
        count[byte]--;
    }

    //copy the sorted elements back to the original array
    for (int i = 0; i < n; i++) {
        arr[i] = output[i];
    }
}

//helper function for radix sort that performs a counting sort on a specific byte of the prefix
void cmp_prefix(struct route_table_entry *arr, struct route_table_entry *output, int n, int shift) {
    int count[256];
    memset(count, 0, sizeof(count));

    //count each byte appereace
    for (int i = 0; i < n; i++) {
        uint32_t val = ntohl(arr[i].prefix);
        int byte = (val >> shift) & 0xff;
        count[byte]++;
    }

    //add counts to find position
    for (int i = 1; i < 256; i++) {
        count[i] += count[i - 1];
    }

    //build the output array backwards to maintain sorting stability
    for (int i = n - 1; i >= 0; i--) {
        uint32_t val = ntohl(arr[i].prefix);
        int byte = (val >> shift) & 0xff;
        output[count[byte] - 1] = arr[i];
        count[byte]--;
    }

    //copy the sorted elements back to the original array
    for (int i = 0; i < n; i++) {
        arr[i] = output[i];
    }
}

//radix sort function that sorts the rtable by mask and then by prefix in O(n)
void radix_sort_rtable(struct route_table_entry *arr, int n) {
    struct route_table_entry *output = malloc(n * sizeof(struct route_table_entry));

    //sorting by mask
    for (int shift = 0; shift < 32; shift += 8) {
        cmp_mask(arr, output, n, shift);
    }

    //sorting by prefix
    for (int shift = 0; shift < 32; shift += 8) {
        cmp_prefix(arr, output, n, shift);
    }

    free(output);
}

//lpm algorithm using binary search
struct route_table_entry *get_best_route(uint32_t ip_dest) {
    struct route_table_entry *best = NULL;
    int left = 0, right = rtable_len - 1;
    
    while (left <= right) {
        int mid = (left + right) / 2;
        if (ntohl(ip_dest & rtable[mid].mask) == ntohl(rtable[mid].prefix)) {
            if (best == NULL || ntohl(rtable[mid].mask) > ntohl(best->mask))
                best = &rtable[mid];
            left = mid + 1;
        } else {
            if (ntohl(ip_dest) < ntohl(rtable[mid].prefix))
                right = mid - 1;
            else
                left = mid + 1;
        }
    }
    
    return best;
}

struct arp_table_entry *arp_table;
int arp_table_len = 0;

//function taht is lookinf int the arp cache for the mac addr that matches the given ip
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	struct arp_table_entry *best = NULL;
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			best = &arp_table[i];
		}
	}
	return best;
}

//function that generates and sends the icmp type 3 (destination unreachable) or
//type 11 (time exceeded)
//it reverses the ethernet macs and embeds the original ip hdr and 8 bytes of the original payload
void icmp_types_3and11_task(uint8_t icmp_type, uint8_t icmp_code, struct ether_hdr *old_eth, struct ip_hdr *old_ip, int interface) {
	char buf[MAX_PACKET_LEN];
	memset(buf, 0, sizeof(buf));

	struct ether_hdr *ethernet = (struct ether_hdr *)buf;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	uint8_t mac[6];
    get_interface_mac(interface, mac);

    //swap macs
    memcpy(ethernet->ethr_dhost, old_eth->ethr_shost, 6);
    memcpy(ethernet->ethr_shost, mac, 6);
    ethernet->ethr_type = htons(ETHERTYPE_IP);

    //build the new ip hdr for icmp response
    ip->ver = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
    ip->id = htons(1);
    ip->frag = 0;
    ip->ttl = 64;
    ip->proto = 1;
    ip->source_addr = inet_addr(get_interface_ip(interface));
    ip->dest_addr = old_ip->source_addr;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

    //build icmp hdr
    icmp->mtype = icmp_type;
    icmp->mcode = icmp_code;
    char *payload = ((char *)icmp + sizeof(struct icmp_hdr));
	memcpy(payload, old_ip, sizeof(struct ip_hdr) + 8);
    icmp->check = 0;
    icmp->check = htons(checksum((uint16_t *)icmp, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));

    send_to_link(ntohs(ip->tot_len) + sizeof(struct ether_hdr), buf, interface);
}

//function that intercepts the icmp requests to the router interface
//and replies with an icmp type 0 (echo reply)
void icmp_type0_task(char *buf, size_t len, int interface) {
	struct ether_hdr *ethernet = (struct ether_hdr *)buf;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    uint8_t mac[6];
    get_interface_mac(interface, mac);

    //swap macs
	memcpy(ethernet->ethr_dhost, ethernet->ethr_shost, 6);
    memcpy(ethernet->ethr_shost, mac, 6);

    //swap ips dest and source
    uint32_t old_src = ip->source_addr;
    ip->source_addr = ip->dest_addr;
    ip->dest_addr = old_src;
    
    ip->ttl = 64; 
    ip->checksum = 0;
    ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

    //build icmp hdr for echo reply
    icmp->mtype = 0;
    icmp->mcode = 0;
    icmp->check = 0;
    size_t icmp_len = ntohs(ip->tot_len) - sizeof(struct ip_hdr);
    icmp->check = htons(checksum((uint16_t *)icmp, icmp_len));

    send_to_link(len, buf, interface);
}

//function that checks if the icmp message is a request (type 8)
void icmp_task(char *buf, size_t len, int interface) {
    struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    //if so sends the echo reply
    if (icmp->mtype == 8) {
        icmp_type0_task(buf, len, interface);
    }
}

//function that generates an arp request packet and broadcasts it to find the mac associated eith a given ip
void arp_request(int interface, uint32_t ip) {
    char buf[MAX_PACKET_LEN];
	memset(buf, 0, sizeof(buf));

    struct ether_hdr *ethernet = (struct ether_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    uint8_t mac_addr[6];
    get_interface_mac(interface, mac_addr);
    uint32_t ip_addr = inet_addr(get_interface_ip(interface));

    //build arp hdr for request
    arp->hw_type = htons(ARPHRD_ETHER);
    arp->proto_type = htons(ETHERTYPE_IP);
    arp->hw_len = 6;
    arp->proto_len = 4;
    arp->opcode = htons(ARPOP_REQUEST);
    arp->sprotoa = ip_addr;
    arp->tprotoa = ip;
    memcpy(arp->shwa, mac_addr, 6);

    //set destination mac for broadcast (ff:ff:ff:ff:ff:ff)
    memset(ethernet->ethr_dhost, 0xff, 6);
    memcpy(ethernet->ethr_shost, mac_addr, 6);
    ethernet->ethr_type = htons(ETHERTYPE_ARP);

    send_to_link(sizeof(*ethernet) + sizeof(*arp), buf, interface);
}

//function that generates an arp replay packet directed to the source of the arp request
void arp_reply(int interface, struct ether_hdr *requested_eth, struct arp_hdr *requested_arp) {
    char buf[MAX_PACKET_LEN];
	memset(buf, 0, sizeof(buf));

    struct ether_hdr *ethernet = (struct ether_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    uint8_t mac_addr[6];
    get_interface_mac(interface, mac_addr);

    //build arp hdr for replay
    arp->hw_type = htons(ARPHRD_ETHER);
    arp->proto_type = htons(ETHERTYPE_IP);
    arp->hw_len = 6;
    arp->proto_len = 4;
    arp->opcode = htons(ARPOP_REPLY);
    arp->sprotoa = requested_arp->tprotoa;
    arp->tprotoa = requested_arp->sprotoa;
    
    memcpy(arp->shwa, mac_addr, 6);
    memcpy(arp->thwa, requested_arp->shwa, 6);

    //the specific requester
    memcpy(ethernet->ethr_dhost, requested_eth->ethr_shost, 6);
    memcpy(ethernet->ethr_shost, mac_addr, 6);
    ethernet->ethr_type = htons(ETHERTYPE_ARP);

    send_to_link(sizeof(*ethernet) + sizeof(*arp), buf, interface);
}

//function that handles incoming arp packets (request and replay)
//if its a request, we replay
//if its a replay, we update the arp cache and empty the queue
void arp_task(char *buf, size_t len, int interface) {
    struct ether_hdr *ethernet = (struct ether_hdr *)buf;
    struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    if (ntohs(arp->opcode) == ARPOP_REQUEST) {
        //the requester asked for the mac addr
        for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
            if (arp->tprotoa == inet_addr(get_interface_ip(i))) {
                arp_reply(i, ethernet, arp);
                break;
            }
        }
    } else if (ntohs(arp->opcode) == ARPOP_REPLY) {
        //received a replay and store it in the cache
        arp_table[arp_table_len].ip = arp->sprotoa;
        memcpy(arp_table[arp_table_len].mac, arp->shwa, 6);
        arp_table_len++;

        queue temp_q = create_queue();
        while (!queue_empty(q)) {
            struct packet *packet = queue_deq(q);

            if (packet->r.next_hop == arp->sprotoa) {
                //found a match so we update the mac hdrsand forward the packets
                struct ether_hdr *eth_pkt = (struct ether_hdr *)packet->buf;
                memcpy(eth_pkt->ethr_dhost, arp->shwa, 6);
                get_interface_mac(packet->r.interface, eth_pkt->ethr_shost);
                
                send_to_link(packet->len, packet->buf, packet->r.interface);
                free(packet);
            } else {
                //match not found so we store the packet to the temporary queue
                queue_enq(temp_q, packet);
            }
        }

        //restore the remaining packets in the main queue
        while (!queue_empty(temp_q)) {
			queue_enq(q, queue_deq(temp_q));
		}
        free(temp_q);
    }
}

//function that handles the forwarding logic presented in the forth lab
void ipv4_task(char *buf, size_t len, int interface) {
    struct ether_hdr *ethernet = (struct ether_hdr *)buf;
	struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

	if (ntohs(ethernet->ethr_type) != ETHERTYPE_IP) {
		return;
	}

    //verify checksum
	uint16_t cs = ntohs(ip->checksum);
	ip->checksum = 0;
	int sum_ok = (checksum((uint16_t *)ip, sizeof(struct ip_hdr)) == cs);
	if (sum_ok == 0) {
        //drop corrupted packet
		return;
	}

    //check if the packet is destinated for this router interface
	int is_for_router = 0;
    for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
        if (ip->dest_addr == inet_addr(get_interface_ip(i))) {
            is_for_router = 1;
            break;
        }
    }
    if (is_for_router) {
        if (ip->proto == 1) icmp_task(buf, len, interface);
        return;
    }

    //find the best route
	struct route_table_entry *best_route = get_best_route(ip->dest_addr);
	if (best_route == NULL) {
        //no route found so we send an icmp type 3
		icmp_types_3and11_task(3, 0, ethernet, ip, interface);
		return;
	}

    //check the ttl
	if (ip->ttl <= 1) {
        //ttl expired so we send an icmpntype 11
		icmp_types_3and11_task(11, 0, ethernet, ip, interface);
		return;
	}
	ip->ttl--;
	ip->checksum = 0;
	ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

    //arp logic
	struct arp_table_entry *best_arp = get_arp_entry(best_route->next_hop);
    if (best_arp != NULL) {
        //we know the mac addr so we update the ethernet hdr and send the packet
        memcpy(ethernet->ethr_dhost, best_arp->mac, 6);
        get_interface_mac(best_route->interface, ethernet->ethr_shost);
		
        send_to_link(len, buf, best_route->interface);
    } else {
        //we do not know the mac addr so we  enqueue the packet and send an arp request
        struct packet *packet = malloc(sizeof(struct packet));
        memcpy(packet->buf, buf, len);
        packet->len = len;
        packet->r = *best_route;
        queue_enq(q, packet);

        arp_request(best_route->interface, best_route->next_hop);
    }
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	rtable_len = read_rtable(argv[1], rtable);
    //sorting the route table using radix sort
    radix_sort_rtable(rtable, rtable_len);

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	arp_table_len = 0;
	q = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// TODO: Implement the router forwarding logic

		/* Note that packets received are in network order,
			any header field which has more than 1 byte will need to be conerted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link, */

		struct ether_hdr *ethernet = (struct ether_hdr *)buf;
		
        //dispatch the packet based on the ethernet type
		if (ntohs(ethernet->ethr_type) == ETHERTYPE_IP) {
			ipv4_task(buf, len, interface);
		} else if (ntohs(ethernet->ethr_type) == ETHERTYPE_ARP) {
			arp_task(buf, len, interface);
		}
	}
}

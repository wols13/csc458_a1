#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

	//Longest prefix match: the mask means how many bits to take into account
	//IP numbers are kept as 4 sequences of 8 bit values
	//Use NOT XOR to determine matching bits
struct sr_if* longestPrefixMatch(struct sr_instance* sr, uint32_t ip) {
	struct sr_if *currIface = sr->if_list;
	struct sr_if *currLongestMatchIface = NULL;
	uint32_t currentMatchedBits, currLMMatchedBits = 0;
	
	//For each interface we have, check its prefix bits and determine which
	//One has the longest match with the provided IP	
	while (currIface != NULL) {
		currentMatchedBits = 0;
		//For each bit location, check if the interface's IP matches the given IP
		for (int i = 31; i >= 7; i--) {
			//Bit shift so we only get the bit of the location we care about
			if (((currIface->ip << 31 - i) >> i) & ((ip << 31 - i) >> i)) {
				currentMatchedBits++;
			} else {
				break;
			}
		}
				
		//Updates longest match if a longer match has been found
		if (currentMatchedBits > currLMMatchedBits) {
			currLongestMatchIface = currIface;
			currLMMatchedBits = currentMatchedBits;
		}
		currIface = currIface->next;
	}
	return currLongestMatchIface;
}

void create_send_icmpMessage(struct sr_instance* sr, uint8_t* packet, uint8_t type, uint8_t code, const char* iface) {
	uint8_t* ICMPpacket = 0;
	unsigned int new_pkt_len;
	unsigned int ethernetPlusIPheaderLength = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
	uint8_t tempDestMac = 0;
	uint32_t tempDestIP = 0;
	
	if (type != 3) {
		new_pkt_len = ethernetPlusIPheaderLength + sizeof(struct sr_icmp_hdr);
		ICMPpacket = malloc(new_pkt_len);
		struct sr_icmp_hdr *ICMPheader = (struct sr_icmp_hdr*)(ICMPpacket + ethernetPlusIPheaderLength);
	} else {
		new_pkt_len = ethernetPlusIPheaderLength + sizeof(struct sr_icmp_t3_hdr);
		ICMPpacket = malloc(new_pkt_len);
		struct sr_icmp_t3_hdr *ICMPheader = (struct sr_icmp_t3_hdr*)(ICMPpacket + ethernetPlusIPheaderLength);
		ICMPheader->unused = 0;
		ICMPheader->next_mtu = 68;
		
		int dataLen = ((struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr))->ip_len) - 20;
		if (dataLen > 8) {
			dataLen = 8;
		}
		
		memcpy(ICMPheader->data, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct sr_ip_hdr));
		memcpy(ICMPheader->data + sizeof(struct sr_ip_hdr), (packet + ethernetPlusIPheaderLength), dataLen);
		
	}
	
	ICMPheader->type = type;
	ICMPheader->code = code;
	ICMPheader->sum = 0;
	ICMPheader->sum = cksum(ICMPheader, new_pkt_len - ethernetPlusIPheaderLength);
	
	//Change IP header dest/source IP and then checksum
	struct sr_ip_hdr *IPheader = (struct sr_ip_hdr*)(ICMPpacket + sizeof(sr_ethernet_hdr));
	memcpy(IPheader, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct sr_ip_hdr);
	tempDestIP = IPheader->ip_src;
	IPheader->ip_src = IPheader->ip_dst;
	IPheader->ip_dst = tempDestIP;
	IPheader->ip_ttl = 70;
	IPheader->ip_len = new_pkt_len - sizeof(struct sr_ethernet_hdr);
	IPheader->ip_p = ip_protocol_icmp;
	IPheader->ip_sum = 0;
	IPheader->ip_sum = cksum(IPheader, sizeof(struct sr_ip_hdr));
	
	
	//Change Ethernet MAC addresses
	struct sr_ethernet_hdr *EthHeader = (struct sr_ethernet_hdr*)ICMPpacket;
	memcpy(EthHeader, packet, sizeof(struct sr_ethernet_hdr);
	tempDestMac = EthHeader->ether_dhost;
	EthHeader->ether_dhost = EthHeader->ether_shost;
	EthHeader->ether_shost = tempDestMac;
	EthHeader->ether_type = ethertype_ip;
			
	sr_send_packet(sr, ICMPpacket, new_pkt_len, iface);
			
	free(ICMPpacket);
}

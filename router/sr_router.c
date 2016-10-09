/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  struct sr_ethernet_hdr* ether_hdr = 0;
  struct sr_ip_hdr* ip_hdr = 0;
  struct sr_if* currInterface = 0;
  struct sr_arpentry* ARPentry = 0;
  struct sr_arpreq* ARPreq = 0;
  uint32_t nexthopIP;
  char *nextiface;
  uint16_t tempChecksum;


  /* fill in code here */
  //Check len meets minimum size
  if (len < sizeof(struct sr_ethernet_hdr) ){
	//Send ICMP reply to sender of type 12 code 2 (Bad length)
	fprintf(stderr , "** Error: packet is wayy to short \n");
    return -1;
  }

  //Extract ethernet header
  ether_hdr = (struct sr_ethernet_hdr*)packet;

  //Need to check if it contains an ARP or IP packet
  //if (ether_hdr->ether_type == ethertype_ip) {
  
  if (ether_hdr->ether_type == ethertype_arp) {
		hand_arpIncomingMessage(packet, sr);
		return 0;
  }
  
	//Extract IP header
	ip_hdr = packet + sizeof(struct sr_ether_hdr);

	//Check IP packet+header size meets minimum size
	if (len - sizeof(struct sr_ethernet_hdr) < sizeof(struct sr_ip_hdr) ){
		//Send ICMP reply to sender of type 12 code 2 (Bad length)
		fprintf(stderr , "** Error: IP packet is wayy to short \n");
		return -1;
	}

	//validate checksum
	tempChecksum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	if (tempChecksum != cksum(ip_hdr, ip_hdr->ip_len)) {
		//Send ICMP reply to sender of type _ code _
		fprintf(stderr , "** Error: checksum mismatch \n");
		return -1;
	}

	//Decrement TTL
	(ip_hdr->ip_ttl)--;

	//Check if TTL = 0 and handle
	if (ip_hdr->ip_ttl < 1) {
		//Send ICMP reply to sender type 11 code 0
		fprintf(stderr , "** Packet's TTL is 0 \n");
		return -1;
	}

	//Recalculate checksum here
	tempChecksum = cksum(ip_hdr, ip_hdr->ip_len);
	ip_hdr->ip_sum = tempChecksum;

	//See if dest ip is one of our interfaces.  If it does, send it out through that interface
	currInterface = sr->if_list;
	while (currInterface != NULL) {
		//This checks if the interface ip is the same as the dest ip in the packet header
		if (currInterface->ip == ip_hdr->ip_dst) {
			//Send it through that interface
			//exit
		}
		currInterface = currInterface->next;
	}

	//Otherwise find longest prefix match (through routing table) and send it there
	// Router struct has a pointer to first routing table entry.  Each router table entry has a pointer
	// to the next (it's a linked list).  We can compare the ip packet's destination to each entry
	//Until we hit next is NULL


	if ((ip_hdr->ip_dst >> 24) == 192) {
		//forward packet to eth1
		nexthopIP = IPtoUint32(192, 168, 2, 2);
		nextiface = "eth1";
	} else if  ((ip_hdr->ip_dst >> 24) == 172){
		//forward packet to eth2
		nexthopIP = IPtoUint32(172, 64, 3, 10);
		nextiface = "eth2";
	} else if  ((ip_hdr->ip_dst >> 24) == 10){
		//forward packet to eth3
		nexthopIP = IPtoUint32(10, 0, 1, 100);
		nextiface = "eth0";
	} else {
		//exit
	}

	ARPentry = sr_arpcache_lookup(&(sr->cache), nexthopIP);
	//MAC Address = ARPentry->mac;
	if (ARPentry != NULL) {
		//send it
		//free(ARPentry); potentially relink
	} else {
		//Add a ARP request onto the ARP request queue
		ARPreq = sr_arpcache_queuereq(&(sr->cache),
							 nexthopIP,
							 packet,
							 len,
							 nextiface);
		//Write and call handle_arpreq
		handle_arpreq(&(sr->cache), ARPreq);

	}


}/* end sr_ForwardPacket */

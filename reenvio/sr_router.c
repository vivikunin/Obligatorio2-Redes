/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

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
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    assert(sr);

    /* Inicializa la caché y el hilo de limpieza de la caché */
    sr_arpcache_init(&(sr->cache));

    /* Inicializa los atributos del hilo */
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    /* Hilo para gestionar el timeout del caché ARP */
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */

/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

  /* COLOQUE AQUÍ SU CÓDIGO*/
  printf("$$$ -> Send ICMP error packet.\n");
  /*
   * SUGERENCIAS:
   * - Construya el cabezal Ethernet y agregue la dirección de destino (debe obtenerla de la caché ARP o enviar una solicitud ARP si no está en la caché)
   * - Construya el cabezal IP
   * - Construya el cabezal ICMP
   * - No olvide calcular los checksums
   * - Envíe el paquete desde la interfaz conectada a la subred de la IP destino
   */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);  
  uint8_t *packet = malloc(len);
  
  memcpy(packet, ipPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_ethernet_hdr_t *ethHdr = (sr_ethernet_hdr_t *) ipPacket;

  struct sr_if *iface = sr_get_interface(sr, sr_LPM(sr, ipDst)->interface);
  
  sr_ethernet_hdr_t* ether_hdr_new_packet = (sr_ethernet_hdr_t*)packet;
  sr_ethernet_hdr_t* ether_hdr_packet = (sr_ethernet_hdr_t*)ipPacket;
  memcpy(ether_hdr_new_packet->ether_shost, iface->addr, ETHER_ADDR_LEN);
  memcpy(ether_hdr_new_packet->ether_dhost, ether_hdr_packet->ether_shost, ETHER_ADDR_LEN);
  /*Consigo el header IP del paquete original */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ipPacket + sizeof(sr_ethernet_hdr_t));

  /* Consigo el header IP del nuevo paquete */
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  // VER ESTO BIEN  
  /* Cambio la longitud del cabezal IP para agregar el ICMP*/
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  /* Establezco el ttl en 64 (predefinido)*/
  new_ip_hdr->ip_ttl = 64;
  /* Cambio el protocolo a ICMP*/
  new_ip_hdr->ip_p = ip_protocol_icmp;
  /* Cambio la direccion IP de destino por la del paquete original*/
  new_ip_hdr->ip_dst = ip_hdr->ip_src;
  /* Cambio la direccion IP de origen por la de la interfaz de salida */
  new_ip_hdr->ip_src = iface->ip;


  


  struct sr_if *iface = sr_get_interface(sr, sr_LPM(sr, ipDst)->interface);
  uint8_t *src_mac = iface->addr;
  //struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip);

  
  
  
  
  
  packet[34] = type;
  packet[35] = code;
  uint16_t checksum = cksum(ipPacket, sizeof(ipPacket));
  packet[36] = (uint8_t *)&(checksum);
  packet[37] = (uint8_t *)&(checksum) + 1;
  for (int i = 0; i < 28; i++){
    packet[38 + i] = ipPacket[i];
  }
  
  
  
  


  /* Envío del paquete ICMP */  
  struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ipDst);
  if (!entry){
    sr_arpcache_queuereq(&(sr->cache), ipDst, (uint8_t *)packet, sizeof(packet), iface->name);
  } else {
    uint8_t *dest_mac = entry->mac;
    packet[0] = *dest_mac;  
    sr_send_packet(sr, (uint8_t *)packet, sizeof(packet),sr_get_interface(sr, sr_LPM(sr, ipDst)->interface)->name);
  }
  
} /* -- sr_send_icmp_error_packet -- */

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* 
  * COLOQUE ASÍ SU CÓDIGO
  * SUGERENCIAS: 
  * - Obtener el cabezal IP y direcciones 
  * - Verificar si el paquete es para una de mis interfaces o si hay una coincidencia en mi tabla de enrutamiento 
  * - Si no es para una de mis interfaces y no hay coincidencia en la tabla de enrutamiento, enviar ICMP net unreachable
  * - Sino, si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply 
  * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
  * - No olvide imprimir los mensajes de depuración
  */

}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* COLOQUE SU CÓDIGO AQUÍ
  
  SUGERENCIAS:
  - Verifique si se trata de un ARP request o ARP reply 
  - Si es una ARP request, antes de responder verifique si el mensaje consulta por la dirección MAC asociada a una dirección IP configurada en una interfaz del router
  - Si es una ARP reply, agregue el mapeo MAC->IP del emisor a la caché ARP y envíe los paquetes que hayan estado esperando por el ARP reply
  
  */
}

/* 
* ***** A partir de aquí no debería tener que modificar nada ****
*/

/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
     ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
     memcpy(ethHdr->ether_shost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

     print_hdrs(copyPacket, currPacket->len);
     sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
     currPacket = currPacket->next;
  }
}

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
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */

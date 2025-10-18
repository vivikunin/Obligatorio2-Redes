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

void sr_init(struct sr_instance *sr)
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
   * PASOS:
   * - Construir  cabezal Ethernet (la dir MAC de destino se obtiene de la cache ARP o se hace ARP request si no está)
   * - Construir el cabezal IP
   * - Construir el cabezal ICMP
   * - Enviar el paquete desde la interfaz conectada a la subred de la IP destino
   */
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *packet = malloc(len);

  // Header IP del paquete original
  // sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ipPacket + sizeof(sr_ethernet_hdr_t));
  // Obtener la interfaz de salida por LPM

  struct sr_rt *lpm = sr_LPM(sr, ipDst);
  struct sr_if *iface = NULL;
  if (!lpm)
  {
    // No hay ruta para el destino, no se puede enviar ICMP error, esta ok?
    free(packet);
    return;
  }
  else
  {
    iface = sr_get_interface(sr, lpm->interface);
  }

  // Construir header IP

  // Header IP del nuevo paquete
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  // Llenar campos del header IP
  new_ip_hdr->ip_tos = 0;                                                     // Type of service 0 para ICMP
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)); // Cambio de longitud del cabezal IP para agregar el ICMP
  new_ip_hdr->ip_id = 0;                                                      // No hay fragmentacion
  new_ip_hdr->ip_off = 0;                                                     // No hay fragmentacion
  new_ip_hdr->ip_ttl = 64;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_src = iface->ip; // Dirección IP de la interfaz de salida
  new_ip_hdr->ip_dst = ipDst;     // Dirección IP de destino es la de origen del paquete original
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = ip_cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  // Construir header ICMP
  if (type == 3 || type == 11 || type == 12)
  {
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0; // PREGUNTAR COMO SE COMPLETA MTU

    // Se copia la cabecera IP original y los primeros 8 bytes del paquete original
    memcpy(icmp_hdr->data, ipPacket, sizeof(sr_ip_hdr_t) + 8);

    // Calculo el checksum del header ICMP
    icmp_hdr->icmp_sum = icmp3_cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  }
  else
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;

    icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
  }

  // Construir el header Ethernet
  sr_ethernet_hdr_t *ether_hdr_new_packet = (sr_ethernet_hdr_t *)packet;
  memcpy(ether_hdr_new_packet->ether_shost, iface->addr, ETHER_ADDR_LEN); // MAC de origen es la de la interfaz de salida
  ether_hdr_new_packet->ether_type = htons(ethertype_ip);

  // Determinar MAC destino en la cache ARP y enviar o hacer ARP request
  struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ipDst);
  if (!entry)
  {
    sr_arpcache_queuereq(&(sr->cache), ipDst, (uint8_t *)packet, len, iface->name);
  }
  else
  {
    // Completar MAC destino y enviar paquete si se encuentra en cache ARP
    uint8_t *dest_mac = entry->mac;
    memcpy(ether_hdr_new_packet->ether_dhost, dest_mac, ETHER_ADDR_LEN);
    print_hdr_ip((uint8_t *)new_ip_hdr);
    printf("[DEBUG] Enviando ICMP error tipo %d, code %d\n", type, code);
    sr_send_packet(sr, (uint8_t *)packet, len, sr_get_interface(sr, sr_LPM(sr, ipDst)->interface)->name);
    free(packet);
  }

} /* -- sr_send_icmp_error_packet -- */

void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet /* lent */,
                         unsigned int len,
                         uint8_t *srcAddr,
                         uint8_t *destAddr,
                         char *interface /* lent */,
                         sr_ethernet_hdr_t *eHdr)
{

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


  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ipDst = ip_hdr->ip_dst;
  print_hdr_ip((uint8_t *)ip_hdr);
  
  // Buscar interfaz en las interfaces del router
  int interfaz_encontrada = 0;
  struct sr_if *if_actual = sr->if_list;
  while (if_actual != NULL && interfaz_encontrada == 0)
  {
    if (if_actual->ip == ipDst)
    {
      interfaz_encontrada = 1;
      break;
    }
    if_actual = if_actual->next;
  }
  if (interfaz_encontrada)
  {
    // El router debe procesar el paquete
    if (ip_hdr->ip_p == ip_protocol_icmp)
    {
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      if (icmp_hdr->icmp_type == 8)
      { // Echo request
        // Construir y enviar echo reply
        sr_send_icmp_echo_reply(sr, packet, len, if_actual);
      }
      // Si es TCP o UDP enviar ICMP port unreachable
    }
    else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17)
    {
      // Enviar ICMP port unreachable
      sr_send_icmp_error_packet(3, 3, sr, ip_hdr->ip_src, packet);
    }
    return;
  }
  else
  {
    // El router debe reenviar el paquete
    // Verificar TTL
    if (ip_hdr->ip_ttl <= 1)
    {
      // Enviar ICMP Time Exceeded al origen del paquete original
      sr_send_icmp_error_packet(11, 0, sr, ip_hdr->ip_src, packet);
      return;
    }
    // Decrementar TTL y recalcular checksum
    ip_hdr->ip_ttl -= 1;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    //Buscar interfaz de salida por LPM
    struct sr_rt *lpm = sr_LPM(sr, ipDst);
    struct sr_if *iface = NULL;
    if (!lpm)
    {
      // No hay ruta para el destino enviar Destination net unreachable (3,0)
      sr_send_icmp_error_packet(3, 0, sr, ip_hdr->ip_src, packet);
      free(packet); //hay que liberar aca?
      return;
    }
    else
    {
      iface = sr_get_interface(sr, lpm->interface);
      sr_send_packet(sr, packet, len, iface->name);
    }
  }
}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
                          uint8_t *packet /* lent */,
                          unsigned int len,
                          uint8_t *srcAddr,
                          uint8_t *destAddr,
                          char *interface /* lent */,
                          sr_ethernet_hdr_t *eHdr)
{

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
                                       struct sr_if *iface)
{

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL)
  {
    ethHdr = (sr_ethernet_hdr_t *)currPacket->buf;
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *)packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len))
  {
    if (pktType == ethertype_arp)
    {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
    else if (pktType == ethertype_ip)
    {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

} /* end sr_ForwardPacket */

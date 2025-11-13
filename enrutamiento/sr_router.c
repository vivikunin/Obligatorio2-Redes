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
#include "sr_rip.h"

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

    /* Inicializa el subsistema RIP */
    sr_rip_init(sr);

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
  /* Reservar memoria para paquete Ethernet + IP + ICMP error (tipo 3/11 etc).*/
  unsigned int pktlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t *packet = malloc(pktlen);
  if (!packet) {
    printf("Failed to allocate memory for ICMP error packet.\n");
    return;
  }

  struct sr_rt *lpm = sr_LPM(sr, ipDst);
  if (!lpm)
  {
    /* No route found: cannot determine outgoing interface */
    free(packet);
    return;
  }
  /* lpm->interface may be NULL; guard before using it */
  if (!lpm->interface) {
    free(packet);
    return;
  }
  struct sr_if *iface = sr_get_interface(sr, lpm->interface);
  if (!iface)
  {
    printf("Interface %s not found for ICMP error packet.\n", lpm->interface);
    free(packet);
    return;
  }
  uint32_t next_hop = (lpm->gw.s_addr != 0) ? lpm->gw.s_addr : ipDst;

  /* Punteros a headers internos */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Construir header IP */
  memset(new_ip_hdr, 0, sizeof(sr_ip_hdr_t));

  /* Version (4 bits) y Header Length (4 bits) en el mismo byte */
  *((uint8_t *)new_ip_hdr) = (4 << 4) | 5;  /* 0x45 */

  new_ip_hdr->ip_tos = 0;
  new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

  new_ip_hdr->ip_id = 0;    /* No hay fragmentacion */
  new_ip_hdr->ip_off = 0;    /* No hay fragmentacion */
  new_ip_hdr->ip_ttl = 64;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_src = iface->ip; /* Dirección IP de la interfaz de salida */
  new_ip_hdr->ip_dst = ipDst;     /* Dirección IP de destino es la de origen del paquete original */
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = ip_cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  /* Construir header ICMP */
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0; 

  /* Se copia la cabecera IP original y los primeros 8 bytes del paquete original */
  uint8_t *orig_ip = ipPacket + sizeof(sr_ethernet_hdr_t);
  printf("Copying original IP header and first 8 bytes of payload into ICMP error packet.\n");
  memcpy(icmp_hdr->data, orig_ip, sizeof(sr_ip_hdr_t) + 8);

  /* Calculo el checksum del header ICMP */
  icmp_hdr->icmp_sum = icmp3_cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /* Construir el header Ethernet */
  printf("Constructing Ethernet header for ICMP error packet.\n");
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN); /* MAC de origen es la de la interfaz de salida */
  eth_hdr->ether_type = htons(ethertype_ip);

  /* Determinar MAC destino en la cache ARP y enviar o hacer ARP request */
  struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), next_hop);
  if (!entry)
  {
    sr_arpcache_queuereq(&(sr->cache), next_hop, (uint8_t *)packet, pktlen, iface->name);
  }
  else
  {
    /* Completar MAC destino y enviar paquete si se encuentra en cache ARP */
    uint8_t *dest_mac = entry->mac;
    memcpy(eth_hdr->ether_dhost, dest_mac, ETHER_ADDR_LEN);
    print_hdrs(packet, pktlen);
    printf("Sending ICMP error type %d, code %d\n", type, code);
    sr_send_packet(sr, packet, pktlen, iface->name);
    free(packet);
    free(entry);
  }

} /* -- sr_send_icmp_error_packet -- */

/* Agregamos funcion para enviar echo reply */
void sr_send_icmp_echo_reply(struct sr_instance *sr,
                             uint8_t *packet,
                             unsigned int len,
                             char *interface)
{
  /* Obtengo la interfaz de salida */
  struct sr_if *iface = sr_get_interface(sr, interface);
  if (!iface) {
    /* Interface not present locally, cannot send reply */
    return;
  }

  /* Cabeceras del paquete original */
  sr_ethernet_hdr_t *eth_orig = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_orig = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  int ip_hdr_len = ip_orig->ip_hl * 4;
  uint16_t orig_ip_len = ntohs(ip_orig->ip_len);
  unsigned int icmp_len = orig_ip_len - ip_hdr_len;

  /* Reservo buffer del mismo tamaño total que el original (ether + ip + icmp payload) */
  uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + orig_ip_len);
  if (!new_packet) {
    return;
  }

  /* Se copia la dirección MAC de la interfaz de salida y
  la dirección MAC origen del paquete original al paquete */
  sr_ethernet_hdr_t *ether_hdr_new_packet = (sr_ethernet_hdr_t *)new_packet;
  memcpy(ether_hdr_new_packet->ether_shost, iface->addr, ETHER_ADDR_LEN);
  memcpy(ether_hdr_new_packet->ether_dhost, eth_orig->ether_shost, ETHER_ADDR_LEN);
  ether_hdr_new_packet->ether_type = htons(ethertype_ip);

  /* IP header: copiar el original y ajustar src/dst / ttl / checksum */
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
  memcpy(new_ip_hdr, ip_orig, ip_hdr_len);
  new_ip_hdr->ip_dst = ip_orig->ip_src;
  new_ip_hdr->ip_src = iface->ip;
  new_ip_hdr->ip_ttl = 64;
  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = ip_cksum(new_ip_hdr, ip_hdr_len);

  /* Crear la cabecera ICMP */
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  sr_icmp_hdr_t *icmp_hdr_orig = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* ICMP: copiar el payload original y poner type=0 code=0, recalcular checksum */
  uint8_t *icmp_src = packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len;
  uint8_t *icmp_dst = new_packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len;
  memcpy(icmp_dst, icmp_src, icmp_len);

  sr_icmp_hdr_t *icmp_new = (sr_icmp_hdr_t *)icmp_dst;
  icmp_new->icmp_type = 0;
  icmp_new->icmp_code = 0;
  icmp_new->icmp_sum = 0;
  icmp_new->icmp_sum = icmp_cksum(icmp_new, icmp_len);

  /* Enviar paquete */
  sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t) + orig_ip_len, iface->name);
  printf("ICMP Echo Reply sent.\n");
  print_hdrs(new_packet, sizeof(sr_ethernet_hdr_t) + orig_ip_len);

  free(new_packet);

} /* -- sr_send_icmp_echo_reply -- */

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
  * - Si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply
  * - Si es para mí o a la IP multicast de RIP, verificar si contiene un datagrama UDP y es destinado al puerto RIP, en ese caso pasarlo al subsistema RIP.
  * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
  * - No olvide imprimir los mensajes de depuración
  */

  printf("Starting sr_handle_ip_packet\n");
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ipDst = ip_hdr->ip_dst;
  print_hdr_ip((uint8_t *)ip_hdr);

  /* Buscar interfaz en las interfaces del router */
  int interfaz_encontrada = 0;
  if (ipDst == htonl(RIP_IP)) {
    interfaz_encontrada = 1;
}
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
    printf("The IP packet is for one of my interfaces.\n");
    /* El router debe procesar el paquete */
    if (ip_hdr->ip_p == ip_protocol_icmp)
    {
      printf("The IP packet is an ICMP packet.\n");
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      printf("ICMP header casteado\n");
      if (icmp_hdr->icmp_type == 8)
      { /* Echo request */
        /* Construir y enviar echo reply */
        printf("Preparing to send ICMP Echo Reply on interface %s\n", interface);
        struct sr_rt *lpm = sr_LPM(sr, ip_hdr->ip_src);
            if (!lpm) {
                /* No hay ruta para responder al origen, enviar net unreachable */
                sr_send_icmp_error_packet(3, 0, sr, ip_hdr->ip_src, packet);
                printf("ICMP Destination Net Unreachable sent for echo reply.\n");
                return;
            }
        printf("LPM found for ICMP Echo Reply.\n");
        if (lpm->interface) {
          /* verify interface exists before sending */
          struct sr_if *out_if = sr_get_interface(sr, lpm->interface);
          if (out_if) {
            sr_send_icmp_echo_reply(sr, packet, len, lpm->interface);
          }
        }
      }
    }
    /* Si es TCP o UDP enviar ICMP port unreachable */
    else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == ip_protocol_udp)
    {
      if (ip_hdr->ip_p == ip_protocol_udp) { 
        /* Verificar si es un paquete RIP */
          printf("The IP packet is a UDP packet.\n");
          sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          if (ntohs(udp_hdr->dst_port) == RIP_PORT) {
              unsigned int ip_off = sizeof(sr_ethernet_hdr_t);
              unsigned int rip_off = ip_off + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t);
              unsigned int rip_len = len - rip_off;
              sr_handle_rip_packet(sr, packet, len, ip_off, rip_off, rip_len, interface);
              return;
          }
      }
      /* Enviar ICMP port unreachable */
      sr_send_icmp_error_packet(3, 3, sr, ip_hdr->ip_src, packet);
      printf("ICMP Port Unreachable sent.\n");
      print_hdrs(packet, len);
    }
    return;
  }
  else
  {
    printf("The received IP packet is NOT for one of my interfaces.\n");
    /* El router debe reenviar el paquete */
    /* Verificar TTL */
    if (ip_hdr->ip_ttl <= 1)
    {
      /* Enviar ICMP Time Exceeded al origen del paquete original */
      sr_send_icmp_error_packet(11, 0, sr, ip_hdr->ip_src, packet);
      printf("ICMP Time Exceeded sent.\n");
      print_hdrs(packet, len);
      return;
    }
    /* Buscar interfaz de salida por LPM */
    struct sr_rt *lpm = sr_LPM(sr, ipDst);
    if (!lpm)
    {
      /* No hay ruta para el destino enviar Destination net unreachable (3,0) */
      sr_send_icmp_error_packet(3, 0, sr, ip_hdr->ip_src, packet);
      return;
    }
    else
    {
      /* lpm->interface should be non-null here; guard and abort if missing */
      if (!lpm->interface) {
        return;
      }
      struct sr_if *iface = sr_get_interface(sr, lpm->interface);
      if (!iface) {
        fprintf(stderr, "Error: interface not found\n");
      return;
      }

      /* Determinar next hop: si la entrada tiene gateway (gw != 0) usarla, si no usar ipDst */
      uint32_t next_hop = 0;
      if (lpm->gw.s_addr != 0)
      {
        next_hop = lpm->gw.s_addr;
      }
      else
      {
        next_hop = ipDst;
      }

      /* HACER COPIA DEL PAQUETE porque vamos a modificarlo */
  uint8_t *pkt_copy = malloc(len);
  if (!pkt_copy) return;
      memcpy(pkt_copy, packet, len);

      sr_ip_hdr_t *ip_copy = (sr_ip_hdr_t *)(pkt_copy + sizeof(sr_ethernet_hdr_t));
      sr_ethernet_hdr_t *eth_copy = (sr_ethernet_hdr_t *)pkt_copy;

       /* Decrementar TTL y recalcular checksum */
      ip_copy->ip_ttl -= 1;
      ip_copy->ip_sum = 0;
      ip_copy->ip_sum = ip_cksum(ip_copy, sizeof(sr_ip_hdr_t));

      /* Buscar MAC destino en la cache ARP */
      struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), next_hop);
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

      if (entry)
      {
        /* Setear MAC origen/dest y enviar */
        printf("The next hops MAC was found in the ARP cache.\n");
        memcpy(eth_copy->ether_shost, iface->addr, ETHER_ADDR_LEN);
        memcpy(eth_copy->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, pkt_copy, len, iface->name);
        printf("Packet successfully forwarded.\n");
        print_hdrs(pkt_copy, len);
        free(pkt_copy);
        free(entry);
        return;
      }
      else
      {

      /* No esta la MAC en cache, actualizar MAC origen y encolar */
      memcpy(eth_copy->ether_shost, iface->addr, ETHER_ADDR_LEN);
      sr_arpcache_queuereq(&(sr->cache), next_hop, pkt_copy, len, iface->name);
      printf("MAC not found in ARP cache, packet queued and ARP request sent.\n");
      print_hdrs(pkt_copy, len);
      }
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

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* COLOQUE SU CÓDIGO AQUÍ

  SUGERENCIAS:
  - Verifique si se trata de un ARP request o ARP reply
  - Si es una ARP request, antes de responder verifique si el mensaje consulta por la dirección MAC asociada a una dirección IP configurada en una interfaz del router
  - Si es una ARP reply, agregue el mapeo MAC->IP del emisor a la caché ARP y envíe los paquetes que hayan estado esperando por el ARP reply

  */

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo las direcciones MAC */
  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, arp_hdr->ar_tha, ETHER_ADDR_LEN);

  /* Obtengo las direcciones IP */
  uint32_t senderIP = arp_hdr->ar_sip;
  uint32_t targetIP = arp_hdr->ar_tip;
  unsigned short op = ntohs(arp_hdr->ar_op);

  /* Verifico si el paquete ARP es para una de mis interfaces */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP);

  if (op == arp_op_request)
  {
    printf("**** -> It is an ARP request.\n");

    /* Si el ARP request es para una de mis interfaces */
    if (myInterface != 0)
    {
      printf("***** -> ARP request is for one of my interfaces.\n");

      /* Construyo un ARP reply y lo envío de vuelta */
      printf("****** -> Construct an ARP reply and send it back.\n");
      memcpy(eHdr->ether_shost, (uint8_t *)myInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eHdr->ether_dhost, (uint8_t *)senderHardAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      arp_hdr->ar_sip = targetIP;
      arp_hdr->ar_tip = senderIP;
      arp_hdr->ar_op = htons(arp_op_reply);

      /* Imprimo el cabezal del ARP reply creado */
      print_hdrs(packet, len);

      sr_send_packet(sr, packet, len, myInterface->name);
    }
  }
  else if (op == arp_op_reply)
  { /* Si es un reply ARP */

    printf("**** -> It is an ARP reply.\n");

    /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");
    struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
    printf("***** -> ARP cache updated,.\n", senderHardAddr, senderIP);

    if (arpReq != NULL)
    { /* Si hay paquetes pendientes */

      printf("****** -> Send outstanding packets.\n");

        /* Obtener una interfaz válida para enviar: preferimos la interfaz almacenada
     en el primer paquete pendiente (ese es el iface que se usó al encolar). */
      struct sr_if *out_if = NULL;
      if (arpReq->packets && arpReq->packets->iface) {
        out_if = sr_get_interface(sr, arpReq->packets->iface);
      }

      /* Si no encontramos iface por el paquete, usar myInterface si no es NULL */
      if (!out_if) {
        out_if = myInterface;
      }

      if (out_if) {
        sr_arp_reply_send_pending_packets(sr, arpReq, senderHardAddr, myInterface->addr, myInterface);
      } else {
        /* No hay interfaz conocida: registrar y descartar/limpiar la req */
        fprintf(stderr, "sr_handle_arp_packet: no iface available to send pending packets for ARP reply %s\n",
                inet_ntoa(*((struct in_addr *)&senderIP)));
      }

      sr_arpreq_destroy(&(sr->cache), arpReq);
    }
    printf("******* -> ARP reply processing complete.\n");
  }
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
     free(copyPacket);
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
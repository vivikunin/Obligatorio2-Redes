/*-----------------------------------------------------------------------------
 * File:  sr_rip.c
 * Date:  Mon Sep 22 23:15:59 GMT-3 2025
 * Authors: Santiago Freire
 * Contact: sfreire@fing.edu.uy
 *
 * Description:
 *
 * Data structures and methods for handling RIP protocol
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_rip.h"

#include "sr_utils.h"


static pthread_mutex_t rip_metadata_lock = PTHREAD_MUTEX_INITIALIZER;

/* Dirección MAC de multicast para los paquetes RIP */
uint8_t rip_multicast_mac[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x09};

/* Función de validación de paquetes RIP */
int sr_rip_validate_packet(sr_rip_packet_t *packet, unsigned int len)
{
    if (len < sizeof(sr_rip_packet_t))
    {
        return 0;
    }

    if (packet->command != RIP_COMMAND_REQUEST && packet->command != RIP_COMMAND_RESPONSE)
    {
        return 0;
    }

    if (packet->version != RIP_VERSION)
    {
        return 0;
    }

    if (packet->zero != 0)
    {
        return 0;
    }

    unsigned int expected_len = sizeof(struct sr_rip_packet_t) +
                                ((len - sizeof(struct sr_rip_packet_t)) / sizeof(struct sr_rip_entry_t)) *
                                    sizeof(struct sr_rip_entry_t);

    if (len != expected_len)
    {
        return 0;
    }

    return 1;
}

int sr_rip_update_route(struct sr_instance *sr,
                        const struct sr_rip_entry_t *rte,
                        uint32_t src_ip,
                        const char *in_ifname)
{
    /*
     * Procesa una entrada RIP recibida por una interfaz.
     *

     *  - Si la métrica anunciada es >= 16:
     *      - Si ya existe una ruta coincidente aprendida desde el mismo vecino, marca la ruta
     *        como inválida, pone métrica a INFINITY y fija el tiempo de garbage collection.
     *      - Si no, ignora el anuncio de infinito.
     *  - Calcula la nueva métrica sumando el coste del enlace de la interfaz; si resulta >=16,
     *    descarta la actualización.
     *  - Si la ruta no existe, inserta una nueva entrada en la tabla de enrutamiento.
     *  - Si la entrada existe pero está inválida, la revive actualizando métrica, gateway,
     *    learned_from, interfaz y timestamps.
     *  - Si la entrada fue aprendida del mismo vecino:
     *      - Actualiza métrica/gateway/timestamps si cambian; si no, solo refresca el timestamp.
     *  - Si la entrada viene de otro origen:
     *      - Reemplaza la ruta si la nueva métrica es mejor.
     *      - Si la métrica es igual y el next-hop coincide, refresca la entrada.
     *      - En caso contrario (peor métrica o diferente camino), ignora la actualización.
     *  - Actualiza campos relevantes: metric, gw, route_tag, learned_from, interface,
     *    last_updated, valid y garbage_collection_time según corresponda.
     *
     * Valores de retorno:
     *  - -1: entrada inválida o fallo al obtener la interfaz.
     *  -  1: la tabla de rutas fue modificada (inserción/actualización/eliminación).
     *  -  0: no se realizaron cambios.
     *
     */
    if (!sr || !rte || !in_ifname) {
        fprintf(stderr, "[RIP] Error: puntero nulo en sr_rip_update_route\n");
        return -1;
    }

    // Convertir todos los campos de la entrada RIP a host order
    uint32_t ip = ntohl(rte->ip);
    uint32_t mask = ntohl(rte->mask);
    uint32_t metric = ntohl(rte->metric);
    uint16_t route_tag = ntohs(rte->route_tag);
    uint32_t network = ip & mask;

    struct sr_rt *existing_route = NULL;

    if (metric >= 16)
    {
        /* Buscar si existe una ruta para esta red en la tabla */

        pthread_mutex_lock(&rip_metadata_lock);

        for (struct sr_rt *rt = sr->routing_table; rt != NULL; rt = rt->next)
        {
            /* Verificar si coincide la red y la máscara */
            if (ntohl(rt->dest.s_addr) == network && ntohl(rt->mask.s_addr) == mask)
            {
                existing_route = rt;
                break;
            }
        }

        /* Verificar si fue aprendida del mismo vecino */
        if (existing_route != NULL && existing_route->learned_from == htonl(src_ip))
        {
            /* Esta ruta existe y fue aprendida desde el mismo vecino (src_ip) */
            existing_route->metric = INFINITY;
            existing_route->valid = 0; /* Marca como inválida */
            existing_route->garbage_collection_time = time(NULL) + RIP_GARBAGE_COLLECTION_SEC;
            pthread_mutex_unlock(&rip_metadata_lock);
            return 1; /* Tabla modificada */
        }

        pthread_mutex_unlock(&rip_metadata_lock);
        return 0; /* Ignorar anuncio de infinito */
    }

    /* Calcular nueva métrica sumando el coste del enlace de la interfaz */
    struct sr_if *in_if = sr_get_interface(sr, in_ifname);
    if (in_if == NULL)
    {
        return -1; /* Fallo al obtener la interfaz */
    }

    uint8_t new_metric = metric + (in_if->cost ? in_if->cost : 1);
    if (new_metric >= 16) {
        return 0; /* Descartar actualización */
    }

    pthread_mutex_lock(&rip_metadata_lock);
    for (struct sr_rt *rt = sr->routing_table; rt != NULL; rt = rt->next)
    {
        /* Verificar si coincide la red y la máscara (convertir campos de la tabla a host order)
           rt->dest.s_addr y rt->mask.s_addr están en network order */
        if (ntohl(rt->dest.s_addr) == network && ntohl(rt->mask.s_addr) == mask)
        {
            existing_route = rt;
            break;
        }
    }
    if (existing_route == NULL)
    {
        /* Insertar nueva entrada en la tabla de enrutamiento */
       sr_add_rt_entry(sr,
        (struct in_addr){htonl(network)},
        (struct in_addr){htonl(src_ip)},
        (struct in_addr){htonl(mask)},
        in_if->name,
        new_metric,
        route_tag,
        htonl(src_ip),
        time(NULL),
        1,
        0);

        pthread_mutex_unlock(&rip_metadata_lock);
        return 1; /* Tabla modificada */
    } else if (existing_route->valid == 0) {
        /* Revivir ruta inválida */
        existing_route->metric = new_metric;
        existing_route->gw.s_addr = htonl(src_ip);
        /* Update interface to the interface where this update arrived */
        strncpy(existing_route->interface, in_ifname, sr_IFACE_NAMELEN - 1);
        existing_route->interface[sr_IFACE_NAMELEN - 1] = '\0';
        existing_route->learned_from = htonl(src_ip);
        existing_route->last_updated = time(NULL);
        existing_route->valid = 1;
        existing_route->garbage_collection_time = 0;

        pthread_mutex_unlock(&rip_metadata_lock);
        return 1; /* Tabla modificada */
    } else if (existing_route->learned_from == htonl(src_ip)) {
        /* Actualizar si cambia métrica/gateway */
        if (existing_route->metric != new_metric || existing_route->gw.s_addr != htonl(src_ip)) {
            existing_route->metric = new_metric;
            existing_route->gw.s_addr = htonl(src_ip);
            strncpy(existing_route->interface, in_ifname, sr_IFACE_NAMELEN - 1);
            existing_route->interface[sr_IFACE_NAMELEN - 1] = '\0';
            existing_route->last_updated = time(NULL);

            pthread_mutex_unlock(&rip_metadata_lock);
            return 1; /* Tabla modificada */
        } else {
            /* Solo refrescar timestamp */
            existing_route->last_updated = time(NULL);

            pthread_mutex_unlock(&rip_metadata_lock);
            return 0; /* No se realizaron cambios */
        }
    } else {
        /* Entrada viene de otro origen */
        if (new_metric < existing_route->metric) {
            /* Reemplazar ruta */
            existing_route->metric = new_metric;
            existing_route->gw.s_addr = htonl(src_ip);
            existing_route->learned_from = htonl(src_ip);
            /* Update interface to the interface where this better route was learned */
            strncpy(existing_route->interface, in_ifname, sr_IFACE_NAMELEN - 1);
            existing_route->interface[sr_IFACE_NAMELEN - 1] = '\0';
            existing_route->last_updated = time(NULL);

            pthread_mutex_unlock(&rip_metadata_lock);
            return 1; /* Tabla modificada */
        } else if (new_metric == existing_route->metric && existing_route->gw.s_addr == htonl(src_ip)) {
            /* Refrescar entrada */
            existing_route->last_updated = time(NULL);

            pthread_mutex_unlock(&rip_metadata_lock);
            return 0; /* No se realizaron cambios */
        }
    }
    pthread_mutex_unlock(&rip_metadata_lock);
    return 0;
}

void sr_handle_rip_packet(struct sr_instance *sr,
                          const uint8_t *packet,
                          unsigned int pkt_len,
                          unsigned int ip_off,
                          unsigned int rip_off,
                          unsigned int rip_len,
                          const char *in_ifname)
{
    if (!sr || !packet || !in_ifname) {
        fprintf(stderr, "[RIP] Error: puntero nulo en sr_handle_rip_packet\n");
        return;
    }
    sr_rip_packet_t *rip_packet = (struct sr_rip_packet_t *)(packet + rip_off);

    /* Validar paquete RIP */

    /* Si es un RIP_COMMAND_REQUEST, enviar respuesta por la interfaz donde llegó, se sugiere usar función auxiliar sr_rip_send_response */

    /* Si no es un REQUEST, entonces es un RIP_COMMAND_RESPONSE. En caso que no sea un REQUEST o RESPONSE no pasa la validación. */

    /* Procesar entries en el paquete de RESPONSE que llegó, se sugiere usar función auxiliar sr_rip_update_route */

    /* Si hubo un cambio en la tabla, generar triggered update e imprimir tabla */

    if (sr_rip_validate_packet(rip_packet, rip_len) == 0)
    {
        printf("RIP packet validation failed.\n");
        return;
    }
    if (rip_packet->command == RIP_COMMAND_REQUEST)
    {
        struct sr_if *interfaz_llegada = sr_get_interface(sr, in_ifname);
        sr_ip_hdr_t *ip_orig_rip_pkt = (sr_ip_hdr_t *)(packet + ip_off);
        sr_rip_send_response(sr, interfaz_llegada, ip_orig_rip_pkt->ip_src); /*Envía a la ip de origen del paquete la respuesta*/
        return;
    }
    else
    {
        int tabla_modificada = 0;
        for (unsigned int i = 0; i < (rip_len - sizeof(sr_rip_packet_t)) / sizeof(sr_rip_entry_t); i++)
        {
            sr_rip_entry_t *entrada = &(rip_packet->entries[i]);
            int resultado = sr_rip_update_route(sr, entrada, ntohl(((sr_ip_hdr_t *)(packet + ip_off))->ip_src), in_ifname);
            if (resultado == -1)
            {
                continue; /* Entrada inválida o fallo al obtener la interfaz */
            }
            else if (resultado == 1)
            {
                tabla_modificada = 1; /* La tabla fue modificada */
            }
        }
        #if ENABLE_TRIGGERED_UPDATE
        if (tabla_modificada)
        {
            // Triggered update: enviar RIP RESPONSE por cada interfaz a la dirección multicast
            struct sr_if *iface = sr->if_list;
            while (iface != NULL) {
                sr_rip_send_response(sr, iface, htonl(RIP_IP)); 
                iface = iface->next;
            }
            printf("RIP routing table modified. Triggered update sent.\n");
            printf("Updated RIP routing table:\n");
            print_routing_table(sr);
        }
        #endif
    }
}

void sr_rip_send_response(struct sr_instance *sr, struct sr_if *interface, uint32_t ipDst)
{
     /* Reservar buffer para paquete completo con cabecera Ethernet */
    
    /* Construir cabecera Ethernet */
    
    /* Construir cabecera IP */
        /* RIP usa TTL=1 */
    
    /* Construir cabecera UDP */
    
    /* Construir paquete RIP con las entradas de la tabla */
        /* Armar encabezado RIP de la respuesta */
        /* Recorrer toda la tabla de enrutamiento  */
        /* Considerar split horizon con poisoned reverse y rutas expiradas por timeout cuando corresponda */
        /* Normalizar métrica a rango RIP (1..INFINITY) */

        /* Armar la entrada RIP:
           - family=2 (IPv4)
           - route_tag desde la ruta
           - ip/mask toman los valores de la tabla
           - next_hop: siempre 0.0.0.0 */

    /* Calcular longitudes del paquete */
    
    /* Calcular checksums */
    
    /* Enviar paquete */

    if (!sr || !interface) {
        fprintf(stderr, "[RIP] Error: puntero nulo en sr_rip_send_response\n");
        return;
    }
    if (!interface->addr) fprintf(stderr, "[RIP] interface->addr es NULL\n");
    if (!interface->name) fprintf(stderr, "[RIP] interface->name es NULL\n");

    /* Contar rutas válidas */
    int num_entries = 0;
    struct sr_rt *rt = sr->routing_table;
    while (rt != NULL) {
        if (rt->valid == 1) {
            num_entries++;
        }
        rt = rt->next;
    }
    
    if (num_entries == 0) {
        printf("[RIP DEBUG] No se envía paquete RIP: num_entries == 0\n");
        return;
    }

    int packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t) + sizeof(sr_rip_packet_t) + num_entries * sizeof(sr_rip_entry_t);        
    int ip_len = packet_length - sizeof(sr_ethernet_hdr_t);
    int udp_len = sizeof(sr_udp_hdr_t) + sizeof(sr_rip_packet_t) + num_entries * sizeof(sr_rip_entry_t);
    printf("Enviando RIP response con: num_entries=%d, packet_length=%d, ip_len=%d, udp_len=%d\n", num_entries, packet_length, ip_len, udp_len);

    /* Reservar buffer */
    uint8_t *buffer = malloc(packet_length);
    if (!buffer) {
        fprintf(stderr, "Error: malloc failed\n");
        return;
    }

    /* Inicializar cabeceras */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)buffer;
    memset(eth_hdr, 0, sizeof(sr_ethernet_hdr_t));
    eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    /*El ether dest host se setea luego de verificar cache ARP*/

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buffer + sizeof(sr_ethernet_hdr_t));
    memset(ip_hdr, 0, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_ttl = 1;
    ip_hdr->ip_src = interface->ip;
    ip_hdr->ip_dst = ipDst;
    ip_hdr->ip_p = ip_protocol_udp;
    ip_hdr->ip_len = htons(ip_len);

    sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(buffer + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    memset(udp_hdr, 0, sizeof(sr_udp_hdr_t));
    udp_hdr->src_port = htons(RIP_PORT);
    udp_hdr->dst_port = htons(RIP_PORT);
    udp_hdr->length = htons(udp_len);
    udp_hdr->checksum = 0;

    /* Inicializar encabezado RIP */
    struct sr_rip_packet_t *rip_packet = (sr_rip_packet_t *)(buffer + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
    rip_packet->command = RIP_COMMAND_RESPONSE;
    rip_packet->version = RIP_VERSION;
    rip_packet->zero = 0;

    /* Inicializar entradas RIP */
    struct sr_rip_entry_t *entries = (struct sr_rip_entry_t *)((uint8_t *)rip_packet + sizeof(sr_rip_packet_t));
    rt = sr->routing_table;
    int entry_idx = 0;
    while (rt != NULL) {
        if (rt->valid == 1) {
            uint32_t metric = rt->metric;
            /* Split horizon con poisoned reverse solo si está activado */
            #if ENABLE_POISONED_REVERSE
            if (ipDst != htonl(RIP_IP)) {
                /* unicast to a neighbor: ipDst is the neighbor IP in network order */
                if (rt->learned_from == ipDst) {
                    metric = INFINITY;
                }
            } else {
                /* multicast: poison routes learned via this outgoing interface */
                if (rt->interface && interface->name &&
                    strncmp(rt->interface, interface->name, sr_IFACE_NAMELEN) == 0) {
                    metric = INFINITY;
                }
            }
            #endif
            if (metric < 1) metric = 1;
            if (metric > INFINITY) metric = INFINITY;

            entries[entry_idx].family_identifier = AF_INET;
            entries[entry_idx].route_tag = htons(rt->route_tag);
            entries[entry_idx].ip = rt->dest.s_addr;
            entries[entry_idx].mask = rt->mask.s_addr;
            entries[entry_idx].next_hop = htonl(0);
            entries[entry_idx].metric = htonl(metric);

            entry_idx++;
        }
        rt = rt->next;
    }

    //  Calcular checksums
    udp_hdr->checksum = 0;
    uint8_t *rip_payload = (uint8_t *)rip_packet;
    udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, rip_payload);
    ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    // Consultar ARP y enviar o encolar
    if (ipDst == htonl(RIP_IP)) {
        memcpy(eth_hdr->ether_dhost, rip_multicast_mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, buffer, packet_length, interface->name);
        free(buffer);
    } else {
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), ipDst);
        if (!arp_entry) {
            sr_arpcache_queuereq(&(sr->cache), ipDst, buffer, packet_length, interface->name);
            // No liberar buffer aquí
            return;
        }
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        free(arp_entry);
        sr_send_packet(sr, buffer, packet_length, interface->name);
        free(buffer);
    }
}

void *sr_rip_send_requests(void *arg)
{
    sleep(3); // Esperar a que se inicialice todo
    if (!arg) {
        fprintf(stderr, "[RIP] Error: puntero nulo en sr_rip_send_requests\n");
        return NULL;
    }
    struct sr_instance *sr = arg;
    if (!sr) {
        fprintf(stderr, "[RIP] Error: sr nulo en sr_rip_send_requests\n");
        return NULL;
    }
    struct sr_if *interface = sr->if_list;
    while (interface != NULL) {
        // Un request por cada interfaz
        int udp_len = sizeof(sr_udp_hdr_t) + sizeof(sr_rip_packet_t) + sizeof(sr_rip_entry_t);
        int ip_len = sizeof(sr_ip_hdr_t) + udp_len;
        int packet_length = sizeof(sr_ethernet_hdr_t) + ip_len;
        uint8_t *pkt = malloc(packet_length);

        // Ethernet
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)pkt;
        memset(eth_hdr, 0, sizeof(sr_ethernet_hdr_t));
        eth_hdr->ether_type = htons(ethertype_ip);
        memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, rip_multicast_mac, ETHER_ADDR_LEN);

        /* Construir cabecera IP */
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
        memset(ip_hdr, 0, sizeof(sr_ip_hdr_t));
        ip_hdr->ip_v = 4; /* version */
        ip_hdr->ip_hl = 5; /* header length */
        ip_hdr->ip_ttl = 1; /* RIP usa TTL=1 */
        ip_hdr->ip_src = interface->ip;
        ip_hdr->ip_dst = htonl(RIP_IP);
        ip_hdr->ip_p = ip_protocol_udp;
        ip_hdr->ip_len = htons(ip_len);

        // UDP
        sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        memset(udp_hdr, 0, sizeof(sr_udp_hdr_t));
        udp_hdr->src_port = htons(RIP_PORT);
        udp_hdr->dst_port = htons(RIP_PORT);
        udp_hdr->length = htons(udp_len);
        udp_hdr->checksum = 0;

        // RIP Request
        struct sr_rip_packet_t *rip_packet = (sr_rip_packet_t *)(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
        rip_packet->command = RIP_COMMAND_REQUEST;
        rip_packet->version = RIP_VERSION;
        rip_packet->zero = 0;

        struct sr_rip_entry_t *entry = (struct sr_rip_entry_t *)((uint8_t *)rip_packet + sizeof(sr_rip_packet_t));
        entry->family_identifier = AF_INET;
        entry->route_tag = 0;
        entry->ip = 0;
        entry->mask = 0;
        entry->next_hop = 0;
        entry->metric = htonl(INFINITY);

        // Checksums
        udp_hdr->checksum = 0;
        udp_hdr->checksum = udp_cksum(ip_hdr, udp_hdr, (uint8_t *)rip_packet);
        ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));

        // Enviar paquete
        sr_send_packet(sr, pkt, packet_length, interface->name);
        free(pkt);
        interface = interface->next;
    }
}


/* Periodic advertisement thread */
void *sr_rip_periodic_advertisement(void *arg)
{
    struct sr_instance *sr = arg;
    if (!sr) {
        fprintf(stderr, "[RIP] Error: sr nulo en sr_rip_periodic_advertisement\n");
        return NULL;
    }

    sleep(2); // Esperar a que se inicialice todo

    // Agregar las rutas directamente conectadas
    /************************************************************************************/
    pthread_mutex_lock(&rip_metadata_lock);
    struct sr_if *int_temp = sr->if_list;
    while (int_temp != NULL)
    {
        struct in_addr ip;
        ip.s_addr = int_temp->ip;
        struct in_addr gw;
        gw.s_addr = 0x00000000;
        struct in_addr mask;
        mask.s_addr = int_temp->mask;
        struct in_addr network;
        network.s_addr = ip.s_addr & mask.s_addr;
        uint8_t metric = int_temp->cost ? int_temp->cost : 1;

        /* Remove matching entries safely while iterating */
        struct sr_rt *prev = NULL;
        struct sr_rt *it = sr->routing_table;
        while (it != NULL) {
            struct sr_rt *next = it->next;
            if (it->dest.s_addr == network.s_addr && it->mask.s_addr == mask.s_addr) {
                /* remove it */
                if (prev == NULL) {
                    /* head */
                    sr->routing_table = next;
                    free(it);
                } else {
                    prev->next = next;
                    free(it);
                }
            } else {
                prev = it;
            }
            it = next;
        }

        sr_add_rt_entry(sr,
                        network,
                        gw,
                        mask,
                        int_temp->name,
                        metric,
                        0,
                        htonl(0),
                        time(NULL),
                        1,
                        0);
        int_temp = int_temp->next;
    }

    pthread_mutex_unlock(&rip_metadata_lock);
    print_routing_table(sr);
    /************************************************************************************/

    /*
        Espera inicial de RIP_ADVERT_INTERVAL_SEC antes del primer envío.
        A continuación entra en un bucle infinito que, cada RIP_ADVERT_INTERVAL_SEC segundos,
        recorre la lista de interfaces (sr->if_list) y envía una respuesta RIP por cada una,
        utilizando la dirección de multicast definida (RIP_IP).
        Esto implementa el envío periódico de rutas (anuncios no solicitados) en RIPv2.
    */
   printf("Entrando a loop de anuncios periódicos\n");
    while (1)
    {
        sleep(RIP_ADVERT_INTERVAL_SEC);
        struct sr_if *interface = sr->if_list;
        while (interface != NULL)
        {
            printf("Enviando anuncio RIP periódico por la interfaz %s\n", interface->name);
            sr_rip_send_response(sr, interface, htonl(RIP_IP));
            interface = interface->next;
        }
    }
    return NULL;
}

/* Chequea las rutas y marca las que expiran por timeout */
void *sr_rip_timeout_manager(void *arg)
{
    if (!arg) {
        fprintf(stderr, "[RIP] Error: puntero nulo en sr_rip_timeout_manager\n");
        return NULL;
    }
    struct sr_instance *sr = arg;
    if (!sr) {
        fprintf(stderr, "[RIP] Error: sr nulo en sr_rip_timeout_manager\n");
        return NULL;
    }

    /*  - Bucle periódico que espera 1 segundo entre comprobaciones.
        - Recorre la tabla de enrutamiento y para cada ruta dinámica (aprendida de un vecino) que no se haya actualizado
        en el intervalo de timeout (RIP_TIMEOUT_SEC), marca la ruta como inválida, fija su métrica a
        INFINITY y anota el tiempo de inicio del proceso de garbage collection.
        - Si se detectan cambios, se desencadena una actualización (triggered update)
        hacia los vecinos y se actualiza/visualiza la tabla de enrutamiento.
        - Imprimir la tabla si hay cambios
        - Se debe usar el mutex rip_metadata_lock para proteger el acceso concurrente
          a la tabla de enrutamiento.
    */
    while(1) {
        pthread_mutex_lock(&rip_metadata_lock);
        time_t current_time = time(NULL);
        int modified = 0;
        struct sr_rt *it = sr->routing_table;
        while (it!=NULL)    
        {
            if (it->valid == 1 && (current_time - it->last_updated) >= RIP_TIMEOUT_SEC)
            {
                   // Solo marcar como inválida si no es conectada
                if (it->gw.s_addr != 0x00000000) {
                    it->metric = INFINITY;
                    it->valid = 0;
                    it->garbage_collection_time = current_time;
                    modified++;
                }
            }
            it = it->next;
        }
        pthread_mutex_unlock(&rip_metadata_lock);
        #if ENABLE_TRIGGERED_UPDATE
        if (modified>0)
        {
            // Triggered update: enviar RIP RESPONSE por cada interfaz a la dirección multicast
            struct sr_if *iface = sr->if_list;
            while (iface != NULL) {
                sr_rip_send_response(sr, iface, htonl(RIP_IP)); 
                iface = iface->next;
            }
            printf("RIP routing table modified. Triggered update sent.\n");
        }
        #endif
        if (modified>0)
        {
            printf("Updated RIP routing table:\n");
            print_routing_table(sr);
        }
        sleep(1);

        
    }
}

/* Chequea las rutas marcadas como garbage collection y las elimina si expira el timer */
void *sr_rip_garbage_collection_manager(void *arg)
{
    printf("[DEBUG] Comenzando sr_rip_garbage_collection_manager\n");

    if (!arg) {
        fprintf(stderr, "[RIP] Error: puntero nulo en sr_rip_garbage_collection_manager\n");
        return NULL;
    }
    struct sr_instance *sr = arg;
    if (!sr) {
        fprintf(stderr, "[RIP] Error: sr nulo en sr_rip_garbage_collection_manager\n");
        return NULL;
    }
    /*
        - Bucle infinito que espera 1 segundo entre comprobaciones.
        - Recorre la tabla de enrutamiento y elimina aquellas rutas que:
            * estén marcadas como inválidas (valid == 0) y
            * lleven más tiempo en garbage collection que RIP_GARBAGE_COLLECTION_SEC
              (current_time >= garbage_collection_time + RIP_GARBAGE_COLLECTION_SEC).
        - Si se detectan eliminaciones, se imprime la tabla.
        - Se debe usar el mutex rip_metadata_lock para proteger el acceso concurrente
          a la tabla de enrutamiento.
    */

    pthread_mutex_lock(&rip_metadata_lock);
    time_t current_time = time(NULL);
    int deleted = 0;
    struct sr_rt *prev = NULL;
    struct sr_rt *it = sr->routing_table;
    while (it != NULL)
    {
        struct sr_rt *next = it->next;
        if (it->valid == 0 && current_time >= it->garbage_collection_time + RIP_GARBAGE_COLLECTION_SEC)
        {
            /* Eliminar ruta de forma segura */
            if (prev == NULL) {
                /* head */
                sr->routing_table = next;
                free(it);
            } else {
                prev->next = next;
                free(it);
            }
            deleted++;
        } else {
            prev = it;
        }
        it = next;
    }
    pthread_mutex_unlock(&rip_metadata_lock);
    if (deleted > 0)
    {
        Debug("-> RIP: Deleted %d routes from the routing table\n", deleted);
        print_routing_table(sr);
    }
    return NULL;
}

/* Inicialización subsistema RIP */
int sr_rip_init(struct sr_instance *sr)
{
    /* Inicializar mutex */
    if (!sr) {
        fprintf(stderr, "[RIP] Error: sr nulo en sr_rip_init\n");
        return -1;
    }
    if (pthread_mutex_init(&sr->rip_subsys.lock, NULL) != 0)
    {
        printf("RIP: Error initializing mutex\n");
        return -1;
    }

    /* Iniciar hilo avisos periódicos */
    if (pthread_create(&sr->rip_subsys.thread, NULL, sr_rip_periodic_advertisement, sr) != 0)
    {
        printf("RIP: Error creating advertisement thread\n");
        pthread_mutex_destroy(&sr->rip_subsys.lock);
        return -1;
    }

    /* Iniciar hilo timeouts */
    pthread_t timeout_thread;
    if (pthread_create(&timeout_thread, NULL, sr_rip_timeout_manager, sr) != 0)
    {
        printf("RIP: Error creating timeout thread\n");
        pthread_cancel(sr->rip_subsys.thread);
        pthread_mutex_destroy(&sr->rip_subsys.lock);
        return -1;
    }

    /* Iniciar hilo garbage collection */
    pthread_t garbage_collection_thread;
    if (pthread_create(&garbage_collection_thread, NULL, sr_rip_garbage_collection_manager, sr) != 0)
    {
        printf("RIP: Error creating garbage collection thread\n");
        pthread_cancel(sr->rip_subsys.thread);
        pthread_mutex_destroy(&sr->rip_subsys.lock);
        return -1;
    }

    /* Iniciar hilo requests */
    pthread_t requests_thread;
    if (pthread_create(&requests_thread, NULL, sr_rip_send_requests, sr) != 0)
    {
        printf("RIP: Error creating requests thread\n");
        pthread_cancel(sr->rip_subsys.thread);
        pthread_mutex_destroy(&sr->rip_subsys.lock);
        return -1;
    }

    return 0;
}

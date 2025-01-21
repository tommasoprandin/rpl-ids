#include "contiki.h"
#include "etimer.h"
#include "mutex.h"
#include "net/ipv6/simple-udp.h"
#include "net/netstack.h"
#include "net/routing/routing.h"
#include "random.h"
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "rpl-icmp6.h"
#include "sys/log.h"
#include "uip.h"
#include "uiplib.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY 1
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define SEND_INTERVAL (10 * CLOCK_SECOND)
#define PRINT_INTERVAL (1 * CLOCK_SECOND)

#define TABLE_ENTRIES 16

/*---------------------------------------------------------------------------*/
struct rpl_stats_entry
{
    uip_ipaddr_t addr;
    uint32_t dio_count;
    uint32_t dao_count;
    uint32_t dis_count;
};
typedef struct rpl_stats_entry rpl_stats_entry_t;
/*---------------------------------------------------------------------------*/
static struct simple_udp_connection udp_conn;
static uint32_t rx_count = 0;
static mutex_t stats_lock;
static rpl_stats_entry_t rpl_stats[TABLE_ENTRIES] = {};
static long last_entry = 0;
/*---------------------------------------------------------------------------*/
PROCESS (udp_client_process, "UDP client");
AUTOSTART_PROCESSES (&udp_client_process);
/*---------------------------------------------------------------------------*/

static long
search_ip (uip_ipaddr_t *ip)
{
    for (int i = 0; i < last_entry; i++)
        {
            if (uip_ipaddr_cmp (&(rpl_stats[i].addr), ip))
                {
                    return i;
                }
        }
    return -1;
}

static void
udp_rx_callback (struct simple_udp_connection *c,
                 const uip_ipaddr_t *sender_addr, uint16_t sender_port,
                 const uip_ipaddr_t *receiver_addr, uint16_t receiver_port,
                 const uint8_t *data, uint16_t datalen)
{

    LOG_INFO ("Received response '%.*s' from ", datalen, (char *)data);
    LOG_INFO_6ADDR (sender_addr);
#if LLSEC802154_CONF_ENABLED
    LOG_INFO_ (" LLSEC LV:%d", uipbuf_get_attr (UIPBUF_ATTR_LLSEC_LEVEL));
#endif
    LOG_INFO_ ("\n");
    rx_count++;
}

static void
print_rpl_stats ()
{
    LOG_DBG ("In print_rpl_stats\n");
    static char buf[60];
    for (int line = 0; line < last_entry; line++)
        {
            LOG_DBG ("On line %d\n", line);
            uiplib_ipaddr_snprint (buf, sizeof (buf), &(rpl_stats[line].addr));
            LOG_INFO ("From neighbor %s:   DIO: %d   DAO: %d   DIS: %d\n", buf,
                      rpl_stats[line].dio_count, rpl_stats[line].dao_count,
                      rpl_stats[line].dis_count);
        }
}

static void
dio_callback (rpl_dio_t *dio, uip_ipaddr_t *from)
{
    static char buf[60];
    while (!mutex_try_lock (&stats_lock))
        ;
    long pos = search_ip (from);

    if (pos < 0)
        {
            uip_ipaddr_copy (&(rpl_stats[last_entry].addr), from);
            rpl_stats[last_entry].dio_count++;
            last_entry++;
        }
    else
        {
            rpl_stats[pos].dio_count++;
        }
    print_rpl_stats ();
    mutex_unlock (&stats_lock);

    uiplib_ipaddr_snprint (buf, sizeof (buf), from);
    LOG_DBG ("Received DIO from: %s\n", buf);
}

static void
dao_callback (rpl_dao_t *dao, uip_ipaddr_t *from)
{
    static char buf[60];
    while (!mutex_try_lock (&stats_lock))
        ;
    long pos = search_ip (from);

    if (pos < 0)
        {
            uip_ipaddr_copy (&(rpl_stats[last_entry].addr), from);
            rpl_stats[last_entry].dao_count++;
            last_entry++;
        }
    else
        {
            rpl_stats[pos].dao_count++;
        }
    print_rpl_stats ();
    mutex_unlock (&stats_lock);

    uiplib_ipaddr_snprint (buf, sizeof (buf), from);
    LOG_DBG ("Received DAO from: %s\n", buf);
}

static void
dis_callback (uip_ipaddr_t *from)
{
    while (!mutex_try_lock (&stats_lock))
        ;
    static char buf[60];
    long pos = search_ip (from);

    if (pos < 0)
        {
            uip_ipaddr_copy (&(rpl_stats[last_entry].addr), from);
            rpl_stats[last_entry].dis_count++;
            last_entry++;
        }
    else
        {
            rpl_stats[pos].dis_count++;
        }
    print_rpl_stats ();
    mutex_unlock (&stats_lock);

    uiplib_ipaddr_snprint (buf, sizeof (buf), from);
    LOG_DBG ("Received DIS from: %s\n", buf);
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD (udp_client_process, ev, data)
{
    static struct etimer periodic_timer;
    static char str[32];
    uip_ipaddr_t dest_ipaddr;
    static uint32_t tx_count;
    static uint32_t missed_tx_count;

    PROCESS_BEGIN ();

    /* Install RPL hooks */
    rpl_install_dio_callback (&dio_callback);
    rpl_install_dao_callback (&dao_callback);
    rpl_install_dis_callback (&dis_callback);

    /* Initialize UDP connection */
    simple_udp_register (&udp_conn, UDP_CLIENT_PORT, NULL, UDP_SERVER_PORT,
                         udp_rx_callback);

    etimer_set (&periodic_timer, random_rand () % SEND_INTERVAL);
    while (1)
        {
            PROCESS_WAIT_EVENT_UNTIL (etimer_expired (&periodic_timer));

            if (NETSTACK_ROUTING.node_is_reachable ()
                && NETSTACK_ROUTING.get_root_ipaddr (&dest_ipaddr))
                {

                    /* Print statistics every 10th TX */
                    if (tx_count % 10 == 0)
                        {
                            LOG_INFO ("Tx/Rx/MissedTx: %" PRIu32 "/%" PRIu32
                                      "/%" PRIu32 "\n",
                                      tx_count, rx_count, missed_tx_count);
                        }

                    /* Send to DAG root */
                    LOG_INFO ("Sending request %" PRIu32 " to ", tx_count);
                    LOG_INFO_6ADDR (&dest_ipaddr);
                    LOG_INFO_ ("\n");
                    snprintf (str, sizeof (str), "Hello bocia %" PRIu32 "",
                              tx_count);
                    simple_udp_sendto (&udp_conn, str, strlen (str),
                                       &dest_ipaddr);
                    tx_count++;
                }
            else
                {
                    LOG_INFO ("Not reachable yet\n");
                    if (tx_count > 0)
                        {
                            missed_tx_count++;
                        }
                }

            /* Add some jitter */
            etimer_set (&periodic_timer,
                        SEND_INTERVAL - CLOCK_SECOND
                            + (random_rand () % (2 * CLOCK_SECOND)));
        }

    PROCESS_END ();
}
/*---------------------------------------------------------------------------*/

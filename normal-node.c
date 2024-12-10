#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "random.h"
#include "sys/log.h"
#include "project-conf.h"

#define LOG_MODULE "Normal"
#define LOG_LEVEL LOG_LEVEL_INFO

#define MIN_INTERVAL (8 * CLOCK_SECOND)
#define MAX_INTERVAL (12 * CLOCK_SECOND)
#define MAX_RETRIES 3

static struct simple_udp_connection udp_conn;
static uint32_t tx_count = 0;
static uint32_t rx_count = 0;
static uint8_t retry_count = 0;

/*---------------------------------------------------------------------------*/
PROCESS(normal_node_process, "Normal Node");
AUTOSTART_PROCESSES(&normal_node_process);

/*---------------------------------------------------------------------------*/
static void udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
    rx_count++;
    retry_count = 0;  // Reset retry counter on successful response
    
    LOG_INFO("Response received from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_(" (len: %u)\n", datalen);
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(normal_node_process, ev, data)
{
    static struct etimer periodic_timer;
    static char msg[64];
    static uip_ipaddr_t dest_ipaddr;
    static clock_time_t interval;

    PROCESS_BEGIN();

    // Initialize UDP connection
    simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                       UDP_SERVER_PORT, udp_rx_callback);

    // Random delay before first transmission (1-5 seconds)
    etimer_set(&periodic_timer, CLOCK_SECOND * (1 + (random_rand() % 5)));

    while(1) {
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

        if(NETSTACK_ROUTING.node_is_reachable() && 
           NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
            
            // Create message with timestamp and sequence number
            snprintf(msg, sizeof(msg), "NORMAL-%lu-%lu", 
                    (unsigned long)clock_seconds(), (unsigned long)tx_count);
            
            LOG_INFO("Sending request %"PRIu32" to ", tx_count);
            LOG_INFO_6ADDR(&dest_ipaddr);
            LOG_INFO_("\n");
            
            simple_udp_sendto(&udp_conn, msg, strlen(msg), &dest_ipaddr);
            tx_count++;

            // Reset retry count on successful transmission
            retry_count = 0;
            
            // Log statistics every 10 packets
            if(tx_count % 10 == 0) {
                LOG_INFO("Stats - Tx: %"PRIu32", Rx: %"PRIu32", Success Rate: %"PRIu32"%%\n",
                         tx_count, rx_count, (rx_count * 100) / tx_count);
            }
            
            // Random interval between MIN and MAX
            interval = MIN_INTERVAL + (random_rand() % (MAX_INTERVAL - MIN_INTERVAL));
            
        } else {
            LOG_INFO("Root not reachable, retry %u of %u\n", retry_count + 1, MAX_RETRIES);
            
            if(++retry_count >= MAX_RETRIES) {
                LOG_WARN("Max retries reached, waiting longer...\n");
                interval = MAX_INTERVAL * 2;
                retry_count = 0;
            } else {
                interval = MIN_INTERVAL;
            }
        }

        etimer_set(&periodic_timer, interval);
    }

    PROCESS_END();
}

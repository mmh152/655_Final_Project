#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "lib/memb.h"
#include "lib/list.h"
#include "sys/log.h"
#include "project-conf.h"

#define LOG_MODULE "Controller"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Traffic patterns and thresholds */
#define TRAFFIC_VECTOR_SIZE 10
#define MIN_PACKETS_FOR_DETECTION 5

/* Structure to track traffic statistics per node */
typedef struct {
    struct node_stat *next;
    uip_ipaddr_t ipaddr;
    uint32_t packet_count;
    uint32_t traffic_vector[TRAFFIC_VECTOR_SIZE];    
    uint8_t vector_index;           
    float risk_score;               
    uint32_t last_packet_time;      
    uint32_t rate_window_count;     
    uint32_t last_cleanup_time;
    bool is_active;
} node_stat_t;

/* Structure for blacklisted nodes */
typedef struct {
    struct blacklist_entry *next;
    uip_ipaddr_t ipaddr;
    uint32_t timestamp;
} blacklist_entry_t;

/* Memory management */
MEMB(node_stats_mem, node_stat_t, MAX_NODES);
MEMB(blacklist_mem, blacklist_entry_t, MAX_BLACKLIST);
LIST(node_stats_list);
LIST(blacklist_list);

static struct simple_udp_connection udp_conn;


/* Baseline vector for normal behavior */
static const uint32_t baseline_vector[TRAFFIC_VECTOR_SIZE] = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64};

/*---------------------------------------------------------------------------*/
/* Square root approximation */
static float approx_sqrt(float x) {
    if (x <= 0) return 0;
    float guess = x / 2.0f;
    for (int i = 0; i < 5; i++) {
        guess = (guess + x / guess) / 2.0f;
    }
    return guess;
}

/*---------------------------------------------------------------------------*/
/* Memory cleanup function */
static void cleanup_old_entries(void) {
    uint32_t current_time = clock_seconds();
    node_stat_t *node;
    node_stat_t *next;

    for(node = list_head(node_stats_list); node != NULL; node = next) {
        next = list_item_next(node);
        
        if (!node->is_active && (current_time - node->last_packet_time) > ENTRY_TIMEOUT) {
            list_remove(node_stats_list, node);
            memb_free(&node_stats_mem, node);
            LOG_INFO("Cleaned up inactive node entry\n");
        }
    }
}

/*---------------------------------------------------------------------------*/
/* Blacklist management */
static bool is_blacklisted(const uip_ipaddr_t *ipaddr) {
    blacklist_entry_t *entry;
    uint32_t current_time = clock_seconds();

    for(entry = list_head(blacklist_list); entry != NULL;) {
        if(uip_ipaddr_cmp(&entry->ipaddr, ipaddr)) {
            if(current_time - entry->timestamp > BLACKLIST_TIMEOUT) {
                blacklist_entry_t *to_remove = entry;
                entry = list_item_next(entry);
                list_remove(blacklist_list, to_remove);
                memb_free(&blacklist_mem, to_remove);
                LOG_INFO("Node removed from blacklist: ");
                LOG_INFO_6ADDR(ipaddr);
                LOG_INFO_("\n");
                return false;
            }
            return true;
        }
        entry = list_item_next(entry);
    }
    return false;
}

/*---------------------------------------------------------------------------*/
static void blacklist_node(const uip_ipaddr_t *ipaddr) {
    if(is_blacklisted(ipaddr)) return;

    blacklist_entry_t *entry = memb_alloc(&blacklist_mem);
    if(entry != NULL) {
        uip_ipaddr_copy(&entry->ipaddr, ipaddr);
        entry->timestamp = clock_seconds();
        list_add(blacklist_list, entry);
        LOG_WARN("Node blacklisted: ");
        LOG_WARN_6ADDR(ipaddr);
        LOG_WARN_("\n");
    } else {
        LOG_WARN("Failed to blacklist node - memory full\n");
    }
}

/*---------------------------------------------------------------------------*/
/* Cosine similarity computation */
static float compute_similarity(const uint32_t *v1, const uint32_t *v2) {
    float dot_product = 0, norm1 = 0, norm2 = 0;
    
    for(int i = 0; i < TRAFFIC_VECTOR_SIZE; i++) {
        dot_product += v1[i] * v2[i];
        norm1 += v1[i] * v1[i];
        norm2 += v2[i] * v2[i];
    }
    
    float norm_product = approx_sqrt(norm1) * approx_sqrt(norm2);
    return (norm_product < 0.000001f) ? 0 : dot_product / norm_product;
}

/*---------------------------------------------------------------------------*/
/* Node statistics management */
static node_stat_t *get_node_stats(const uip_ipaddr_t *ipaddr) {
    node_stat_t *stats;
    
    // Try to find existing entry
    for(stats = list_head(node_stats_list); stats != NULL; stats = list_item_next(stats)) {
        if(uip_ipaddr_cmp(&stats->ipaddr, ipaddr)) {
            stats->is_active = true;
            return stats;
        }
    }
    
    // Clean up if needed
    if(list_length(node_stats_list) >= MAX_NODES) {
        cleanup_old_entries();
    }
    
    // Create new entry if possible
    stats = memb_alloc(&node_stats_mem);
    if(stats != NULL) {
        memset(stats, 0, sizeof(node_stat_t));
        uip_ipaddr_copy(&stats->ipaddr, ipaddr);
        stats->last_cleanup_time = clock_seconds();
        stats->is_active = true;
        list_add(node_stats_list, stats);
        
        LOG_INFO("New node tracked: ");
        LOG_INFO_6ADDR(ipaddr);
        LOG_INFO_("\n");
    }
    
    return stats;
}

/*---------------------------------------------------------------------------*/
/* Attack detection */
static bool detect_attack(node_stat_t *node, uint16_t datalen) {
    uint32_t current_time = clock_seconds();
    float risk_score = 0;
    
    // Update traffic vector
    node->traffic_vector[node->vector_index] = datalen;
    node->vector_index = (node->vector_index + 1) % TRAFFIC_VECTOR_SIZE;
    node->packet_count++;
    
    // Rate limiting check
    if(current_time == node->last_packet_time) {
        node->rate_window_count++;
        if(node->rate_window_count > RATE_LIMIT_PACKETS) {
            risk_score += RATE_WEIGHT;
            LOG_WARN("Rate limit exceeded for ");
            LOG_WARN_6ADDR(&node->ipaddr);
            LOG_WARN_("\n");
        }
    } else {
        node->rate_window_count = 1;
        node->last_packet_time = current_time;
    }
    
    // Pattern analysis
    if(node->packet_count >= MIN_PACKETS_FOR_DETECTION) {
        float similarity = compute_similarity(node->traffic_vector, baseline_vector);
        if(similarity < DETECTION_THRESHOLD) {
            risk_score += PATTERN_WEIGHT;
            LOG_INFO("Abnormal traffic pattern (similarity: %f)\n", similarity);
        }
    }
    
    node->risk_score = risk_score;
    
    // Attack detection
    if(risk_score >= ATTACK_THRESHOLD) {
        LOG_WARN("Attack detected! Risk score: %f\n", risk_score);
        return true;
    }
    
    return false;
}

/*---------------------------------------------------------------------------*/
/* UDP callback */
static void udp_rx_callback(struct simple_udp_connection *c,
                          const uip_ipaddr_t *sender_addr,
                          uint16_t sender_port,
                          const uip_ipaddr_t *receiver_addr,
                          uint16_t receiver_port,
                          const uint8_t *data,
                          uint16_t datalen)
{
    // Check blacklist first
    if(is_blacklisted(sender_addr)) {
        LOG_WARN("Dropped packet from blacklisted node: ");
        LOG_WARN_6ADDR(sender_addr);
        LOG_WARN_("\n");
        return;
    }

    // Get or create node statistics
    node_stat_t *node = get_node_stats(sender_addr);
    if(node == NULL) {
        LOG_WARN("Failed to allocate memory for node statistics\n");
        return;
    }
    
    // Detect potential attacks
    if(detect_attack(node, datalen)) {
        blacklist_node(sender_addr);
        node->is_active = false;
        return;
    }
    
    // Process legitimate packet
    LOG_INFO("Legitimate packet from ");
    LOG_INFO_6ADDR(sender_addr);
    LOG_INFO_(" (risk: %f)\n", node->risk_score);
    
    // Send response for legitimate traffic
    simple_udp_sendto(&udp_conn, data, datalen, sender_addr);
}

/*---------------------------------------------------------------------------*/
PROCESS(sdn_controller_process, "SDN Controller with DDoS Protection");
AUTOSTART_PROCESSES(&sdn_controller_process);

PROCESS_THREAD(sdn_controller_process, ev, data)
{
    static struct etimer periodic_timer;
    
    PROCESS_BEGIN();
    
    // Initialize as root node
    NETSTACK_ROUTING.root_start();
    
    // Initialize memory management
    memb_init(&node_stats_mem);
    memb_init(&blacklist_mem);
    list_init(node_stats_list);
    list_init(blacklist_list);
    
    // Register UDP connection
    simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                       UDP_CLIENT_PORT, udp_rx_callback);
    
    // Set up periodic cleanup timer
    etimer_set(&periodic_timer, CLEANUP_INTERVAL * CLOCK_SECOND);
    
    LOG_INFO("SDN Controller started with DDoS protection\n");
    
    while(1) {
        PROCESS_WAIT_EVENT();
        
        if(etimer_expired(&periodic_timer)) {
            cleanup_old_entries();
            etimer_reset(&periodic_timer);
        }
    }
    
    PROCESS_END();
}

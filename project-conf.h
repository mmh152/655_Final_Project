#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Logging Configuration */
#define LOG_LEVEL_APP LOG_LEVEL_INFO

/* Remove DEBUG definition as it conflicts */
/* #define DEBUG 0 */

/* Network configuration */
#define NETSTACK_CONF_WITH_IPV6 1
#define UIP_CONF_BUFFER_SIZE 240
#define NETSTACK_MAX_ROUTE_ENTRIES 8

/* UDP ports */
#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/* DDoS Detection Configuration */
#define MAX_NODES 4              
#define PACKET_THRESHOLD 10      
#define PACKET_WINDOW 5          
#define DETECTION_THRESHOLD 0.6   

/* Risk Score Configuration */
#define RATE_WEIGHT 0.4         
#define PATTERN_WEIGHT 0.6      
#define ATTACK_THRESHOLD 0.8     

/* Memory Management */
#define CLEANUP_INTERVAL 10     
#define ENTRY_TIMEOUT 30        

/* Rate Limiting */
#define RATE_LIMIT_WINDOW 1     
#define RATE_LIMIT_PACKETS 5     

/* Blacklist Configuration */
#define MAX_BLACKLIST 4         
#define BLACKLIST_TIMEOUT 60    

#endif /* PROJECT_CONF_H_ */


#include <netinet/in.h>
#include <arpa/inet.h>

#include "hash_table.h"
#include "trie.h"
#include "msgs.h"

#define LOG_NAME "bwd"
#define LOG_VERSION "1.1"
#define MAX_STRING 1024
#define MAX_PREF_PER_RULE 16	/* max. number of prefixes per riule */

/* general options of bwd */
typedef struct options_s {

	int debug;			/* debug mode */
	int window;			/* window size for evaluating */
	int step;			/* reporting stem in Mbps */
	int drop_delay;		/* wait with drop n secs */
	char config_file[MAX_STRING];		/* config gile name */

//	hash_table_t hash_table;
#define FLOW_DIR_SRC 	0
#define FLOW_DIR_DST 	1
	TTrieNode *trie4[2];
	TTrieNode *trie6[2];

} options_t;

/* address rule structure */
typedef struct ip_prefix_s {

	int af;			/* AF_INT, AF_INET6 */
	int flow_dir;		/* direction FLOW_DIR_SRC|FLOW_DIR_DST */
	int prefixlen;
	union {
		uint32_t v4;
		uint32_t v6[4];
	} ip;
} ip_prefix_t;


/* statistics node */
typedef struct stat_node_s {
	long int bytes;
	long int pkts;
	long int limit_bytes;
	long int limit_pkts;
	int updated;
	int windowstart;
	int laststep;
	int lastrep;

	int num_prefixes; 	/* number of prefixes */
	ip_prefix_t prefixes[MAX_PREF_PER_RULE];;
} stat_node_t;


int parse_config(options_t *opt);
stat_node_t * stat_node_new(options_t *opt);
int stat_node_add(options_t *opt, int af, int direction, char *ipaddr, long int prefixlen, stat_node_t *stat_node);
void stat_node_log(options_t *opt, stat_node_t *stat_node);


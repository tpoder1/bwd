
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hash_table.h"
#include "trie.h"
#include "msgs.h"
#include "bit_array.h"

#define LOG_NAME "bwd"
#define LOG_VERSION "1.1"
#define MAX_STRING 1024
#define MAX_PREF_PER_RULE 16	/* max. number of prefixes per riule */

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
	int num_prefixes; 				/* number of prefixes */
	ip_prefix_t prefixes[MAX_PREF_PER_RULE];;
	int limit_bps;					/* set limits */
	int limit_pps;
	double treshold;   				/* treshold (0.78 = 78%) */
	int window_size; 	 			/* window size to evaluate (in seconds) */
	int remove_delay;				/* delay before shaping rule is removed */
	int dynamic_ipv4;				/* prefix size for dynamic rules */
	int dynamic_ipv6;

	unsigned long int stats_bytes;		/* real byte/packet count */
	unsigned long int stats_pkts;

	int last_updated;		/* when the statistics were updated */
	int window_reset;		/* when the current window started */
	int time_reported;		/* when last report was done - 0 if not reported */
	int id;					/* assigned unique id */

	struct stat_node_s  *next_node;

} stat_node_t;


/* general options of bwd */
typedef struct options_s {

	int debug;						/* debug mode */
	int foreground;					/* do not daemonize */
	char device[MAX_STRING]; 	/* interface name */
	double treshold;   				/* treshold (0.78 = 78%) */
	int window_size; 	 			/* window size to evaluate (in seconds) */
	int remove_delay;				/* delay before shaping rule is removed */
	int expire_interval;			/* how ofter check for expired records */
	int last_expire_check;			/* timestam of last expire check */
	char config_file[MAX_STRING];	/* config gile name */
	char dbdump_file[MAX_STRING];	/* status file for database dump */
	char pid_file[MAX_STRING];		/* filw with PID */
	char exec_new[MAX_STRING];		/* command to exec new rule */
	char exec_del[MAX_STRING];		/* command to exec to remove rule */
	int	id_num;						/* number of numbers in id pool  */
	int	id_last;					/* last assigned id (without offset) */
	int	id_offset;					/* ide offset (100 = star with id 100) */

//	hash_table_t hash_table;
#define FLOW_DIR_SRC 	0
#define FLOW_DIR_DST 	1

	/* structures used by the current config */
	TTrieNode *op_trie4[2];
	TTrieNode *op_trie6[2];
	stat_node_t *op_root_node;

	/* temporary structures for loading config */
	TTrieNode *cf_trie4[2];
	TTrieNode *cf_trie6[2];
	stat_node_t *cf_root_node;

	/* bit array of allocated ids */
	bit_array_t ids;

} options_t;

typedef enum action_s {
	ACTION_DUMP,
	ACTION_NEW,
	ACTION_DEL
} action_t;

typedef enum config_s {
	CONFIG_CF,
	CONFIG_OP,
} config_t;



int parse_config(options_t *opt);
stat_node_t * stat_node_new(options_t *opt, config_t ct);
int stat_node_add(options_t *opt, int af, int direction, char *ipaddr, long int prefixlen, stat_node_t *stat_node);
void stat_node_log(FILE *fh, action_t action, options_t *opt, stat_node_t *stat_node);


int exec_node_cmd(options_t *opt, stat_node_t *stat_node, action_t action);


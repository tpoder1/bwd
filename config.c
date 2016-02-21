
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <syslog.h>
#include "msgs.h"
#include "bwd.h"

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

#ifndef YY_TYPEDEF_YY_BUFFER_STATE
#define YY_TYPEDEF_YY_BUFFER_STATE
typedef struct yy_buffer_state *YY_BUFFER_STATE;
#endif

int parse_config(options_t *opt) {

	yyscan_t scanner;
//	YY_BUFFER_STATE buf;
	int parse_ret;
	FILE * fp;

	fp = fopen(opt->config_file, "r");

	if (fp == NULL) {
		msg(MSG_INFO, "Can't open file %s (%s)", opt->config_file, strerror(errno));
		return 0;
	}

	yylex_init(&scanner);
	yyset_in(fp, scanner);

    parse_ret = yyparse(scanner, opt);
//    parse_ret = yyparse(scanner);

	yylex_destroy(scanner);

	if (parse_ret == 0) {
		msg(MSG_INFO, "Config file parsed");

		/* switch to the new configuration */
		opt->op_trie4[FLOW_DIR_SRC] = opt->cf_trie4[FLOW_DIR_SRC];
		opt->op_trie4[FLOW_DIR_DST] = opt->cf_trie4[FLOW_DIR_DST];
		opt->op_trie6[FLOW_DIR_SRC] = opt->cf_trie6[FLOW_DIR_SRC];
		opt->op_trie6[FLOW_DIR_DST] = opt->cf_trie6[FLOW_DIR_DST];
		opt->op_root_node = opt->cf_root_node;

		return 1;
	} else {

		/* keep the old config */
		msg(MSG_ERROR, "Can't load config file");
		return 0;
	}
}

stat_node_t * stat_node_new(options_t *opt) {
	stat_node_t *tmp;

	tmp = malloc(sizeof(stat_node_t));

	if (tmp == NULL) {
		return NULL;
	}	

	memset(tmp, 0x0, sizeof(stat_node_t));

	tmp->window_size = opt->window_size;
	tmp->remove_delay = opt->remove_delay;
	tmp->treshold = opt->treshold;

	tmp->next_node = opt->cf_root_node;
	opt->cf_root_node = tmp;

	return tmp;
}

int stat_node_add(options_t *opt, int af, int direction, char *ipaddr, long int prefixlen, stat_node_t *stat_node) {

	char buf[MAX_STRING];

	ip_prefix_t *ppref;

	ppref = &stat_node->prefixes[stat_node->num_prefixes];

	ppref->prefixlen = prefixlen;
	ppref->af = af;
	ppref->flow_dir = direction; 

	if (inet_pton(af, ipaddr, &buf)) {

		switch (af) {

			case AF_INET:	/* IPV4 */
				addPrefixToTrie((void *)&buf, prefixlen, stat_node, &(opt->cf_trie4[direction]));
				memcpy(&ppref->ip.v4, &buf, sizeof(ppref->ip.v4));
				break;
			case AF_INET6: /* IPV6 */
				addPrefixToTrie((void *)&buf, prefixlen, stat_node, &(opt->cf_trie6[direction]));
				memcpy(&ppref->ip.v4, &buf, sizeof(ppref->ip.v6));
				break;
			default:
				return 0;
		}
		
		stat_node->num_prefixes++;
		return 1;
	}

	return 0;

}

void stat_node_log(FILE *fh, action_t action, options_t *opt, stat_node_t *stat_node) {

	int i;
	ip_prefix_t *ppref;
	char buf[MAX_STRING];
	char *actionstr;
	

	if (opt == NULL) {

		return;

	}

	switch(action) {
		case ACTION_DUMP: actionstr = "dump"; break;
		case ACTION_NEW:  actionstr = "new"; break;
		case ACTION_DEL:  actionstr = "del"; break;
		default: actionstr = "?"; break;
	}

	fprintf(fh, "action: %s\n", actionstr);

	for (i = 0; i < stat_node->num_prefixes; i++) {
		ppref = &stat_node->prefixes[i];
			
		switch (ppref->af) {
			case AF_INET: 
				inet_ntop(ppref->af, &ppref->ip.v4, (void *)&buf, MAX_STRING - 1);
				break;
			case AF_INET6: 
				inet_ntop(ppref->af, &ppref->ip.v6, (void *)&buf, MAX_STRING - 1);
				break;
			default:
				buf[0] = '\0';
			}

		fprintf(fh, "%sip: %s/%d \n", 
						ppref->flow_dir == FLOW_DIR_SRC ? "src" : "dst", 
						buf, ppref->prefixlen );

	}

	fprintf(fh, "limit_bps: %d\n", stat_node->limit_bps);
	fprintf(fh, "limit_pps: %d\n", stat_node->limit_pps);
	fprintf(fh, "current_bps: %ld\n", stat_node->stats_bytes / stat_node->window_size * 8);
	fprintf(fh, "current_pps: %ld\n", stat_node->stats_pkts / stat_node->window_size);
	fprintf(fh, "dynamic_ipv4: %d\n", stat_node->dynamic_ipv4);
	fprintf(fh, "dynamic_ipv6: %d\n", stat_node->dynamic_ipv6);
	fprintf(fh, "treshold: %f\n", stat_node->treshold);
	fprintf(fh, "id: %d\n", stat_node->id);
//		printf("node: %p\n", stat_node);
//		printf("next_node: %p\n", stat_node->next_node);

}


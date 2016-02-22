
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


/* compare items of two nodes */
int stats_node_cmp(stat_node_t *n1, stat_node_t *n2) {

	if (n1->num_prefixes != n2->num_prefixes) { return 1; }
	if (n1->limit_bps != n2->limit_bps) { return 1; }
	if (n1->limit_pps != n2->limit_pps) { return 1; }
	if (n1->treshold != n2->treshold) { return 1; }
	if (n1->window_size != n2->window_size) { return 1; }
	if (n1->remove_delay != n2->remove_delay) { return 1; }
	if (n1->dynamic_ipv4 != n2->dynamic_ipv4) { return 1; }
	if (n1->dynamic_ipv6 != n2->dynamic_ipv6) { return 1; }

	return memcmp(n1->prefixes, n2->prefixes, sizeof(n2->prefixes));

}


/* walk via all _op nodes 
  if  the node is active then check configuration and if 
  the config is differend delete the rule 
*/
int update_config(options_t *opt) {

	stat_node_t *stat_node, *new_stat_node;
	TTrieNode *pTn, *trie;
	ip_prefix_t *ppref;
	int addrlen;
	char *addr;

	while (opt->op_root_node != NULL) {

		stat_node = opt->op_root_node;
		opt->op_root_node = stat_node->next_node;

		/* active node */
		if (stat_node->time_reported > 0) {

			/* lookup for simmilar node in the new configuration */
			/* check firt prefix is enough to do it */
			if (stat_node->num_prefixes > 0) {
				ppref = &stat_node->prefixes[0];
			
				switch (ppref->af) {
					case AF_INET: 
						addrlen = sizeof(uint32_t);
						trie = opt->cf_trie4[ppref->flow_dir];
						addr = (char *)&ppref->ip.v4;
						break;
				case AF_INET6: 
						addrlen = sizeof(uint32_t[4]);
						trie = opt->cf_trie6[ppref->flow_dir];
						addr = (char *)&ppref->ip.v6;
						break;
				default:
						addrlen = 0;
						trie = NULL;
						addr = NULL;
						break;
				}

				pTn = lookupAddress((void *)addr, addrlen * 8, trie);

				if (pTn != NULL && pTn->hasValue) {
					new_stat_node = pTn->Value;

					/* compare the content of the old and the new node */
					if (stats_node_cmp(stat_node, new_stat_node) == 0) {
						/* new node have same configuration - just copy some data from the old one */
						new_stat_node->stats_bytes = stat_node->stats_bytes;
						new_stat_node->stats_pkts = stat_node->stats_pkts;
						new_stat_node->last_updated = stat_node->last_updated;
						new_stat_node->window_reset = stat_node->window_reset;
						new_stat_node->time_reported = stat_node->time_reported;
						new_stat_node->id = stat_node->id;
					} else {
						/* differend configuration - remove the existing rule */
						exec_node_cmd(opt, stat_node, ACTION_DEL);
					}
				}


			} else {
				/* therw were no prefixes defined so the rule might not exist, just for sure remove rule */
				exec_node_cmd(opt, stat_node, ACTION_DEL);
			}

		}

		free(stat_node);

    }


	/* cleanup trie structures */
	return 1;	
}

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

	//fclose(fp);

	if (parse_ret == 0) {
		msg(MSG_INFO, "Config file parsed");

		/* switch to the new configuration */
		if (update_config(opt)) {
			freeTrieNode(opt->op_trie4[FLOW_DIR_SRC]);
			freeTrieNode(opt->op_trie4[FLOW_DIR_DST]);
			freeTrieNode(opt->op_trie6[FLOW_DIR_SRC]);
			freeTrieNode(opt->op_trie6[FLOW_DIR_DST]);

			opt->op_trie4[FLOW_DIR_SRC] = opt->cf_trie4[FLOW_DIR_SRC];
			opt->op_trie4[FLOW_DIR_DST] = opt->cf_trie4[FLOW_DIR_DST];
			opt->op_trie6[FLOW_DIR_SRC] = opt->cf_trie6[FLOW_DIR_SRC];
			opt->op_trie6[FLOW_DIR_DST] = opt->cf_trie6[FLOW_DIR_DST];
			/* allocated memory for opt->op_root_node is released by update_config */
			opt->op_root_node = opt->cf_root_node;

			/* clanup old data */
			opt->cf_trie4[FLOW_DIR_SRC] = NULL;
			opt->cf_trie4[FLOW_DIR_DST] = NULL;
			opt->cf_trie6[FLOW_DIR_SRC] = NULL;
			opt->cf_trie6[FLOW_DIR_DST] = NULL;
			opt->cf_root_node = NULL;
			return 1;
		} else {
			return 0;
		}

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

		fprintf(fh, "%sip%c: %s/%d \n", 
						ppref->flow_dir == FLOW_DIR_SRC ? "src" : "dst", 
						ppref->af == AF_INET ? '4' : '6',
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



#include <stdio.h>
#include "conf.h"
#include "sysdep.h"
#include <time.h>
//#include "dataflow.h"

//#include <pcap.h>
//#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "bwd.h"
#include "msgs.h"
#include "daemonize.h"
//#include <netinet/tcp.h>
#include <pthread.h>

#define SCAN_TIME 10*1000		/* scan loop - every 10 msecs */
#define UPDATES_IN_STEP 50		/* max number of updates (new/del) in one cycle */

pcap_t *dev;		// pouzivane rozhrani 

long last_pkt = 0;
long last_err = 0;
//long cnt = 0;
//int fl_debug = 0;
//int window = 10;	/* window size for evaluating */
//int step = 1;		/* reporting stem in Mbps */
//int drop_delay = 0;		/* wait with drop n secs */

options_t *active_opt;
int received_hup = 0;
int received_usr1 = 0;
int received_term = 0;


void terminates(int sig) {

	received_term = 1;
}
    
void dump_nodes_db(options_t *opt);
void sig_usr1(int sig) {

	received_usr1 = 1;
    
//    FlowExport();
}

void sig_hup(int sig) {

	received_hup = 1;
    
}


int get_next_id(options_t *opt) {

	int i = 0;

	if (opt->id_num	== 0) {
		return 0;
	}

	/* the id is free */
	while (bit_array_get(&opt->ids, opt->id_last) != 0) {

		opt->id_last++;
		i++;

		if (opt->id_last >= opt->id_num) {
			opt->id_last = 0;
		}
	
		if (i > opt->id_num) {
			msg(MSG_ERROR, "Can not find free id for rule.");
			return 0;
		}
	}

	bit_array_set(&opt->ids, opt->id_last, 1);

	return opt->id_last;
}

int exec_cmd(options_t *opt, action_t action) {

	char cmd[MAX_STRING];
	FILE *fh;

	switch (action) {
		case ACTION_INIT: snprintf(cmd, MAX_STRING, "%s %s", opt->exec_init, "init"); break;
		case ACTION_FINISH: snprintf(cmd, MAX_STRING, "%s %s", opt->exec_finish, "finish"); break;
		default: return 0; break;
	}

	fh = popen(cmd, "w");

	if (fh == NULL) {
		msg(MSG_ERROR, "Can execute external command %s.", cmd);
		return 0;
	}

	fprintf(fh, "device: %s\n", opt->device);
	fflush(fh);

	if (opt->debug > 5) {
		fprintf(stdout, "Trying to execute command %s.\n", cmd);
	}

	if ( pclose(fh) != 0 ) {
		msg(MSG_ERROR, "External command %s was not executed.", cmd);
		return 0;
	}

	return 1;
}

int exec_node_cmd(options_t *opt, stat_node_t *stat_node, action_t action) {

	char cmd[MAX_STRING];
	FILE *fh;

	/* release id */
	if (action == ACTION_NEW && opt->id_num != 0) {
		stat_node->id = get_next_id(opt) + opt->id_offset;
	}

	switch (action) {
		case ACTION_NEW: snprintf(cmd, MAX_STRING, "%s %s %d", opt->exec_new, "new", stat_node->id); break;
		case ACTION_DEL: snprintf(cmd, MAX_STRING, "%s %s %d", opt->exec_new, "del", stat_node->id); break;
		default: return 0; break;
	}


	fh = popen(cmd, "w");

	if (fh == NULL) {
		msg(MSG_ERROR, "Can execute external command %s.", cmd);
		return 0;
	}

	stat_node_log(fh, action, opt, stat_node);
	fflush(fh);

	if (opt->debug > 5) {
		fprintf(stdout, "Trying to execute command %s.\n", cmd);
		stat_node_log(stdout, action, opt, stat_node);
		fprintf(stdout, "\n");
	}

	if ( pclose(fh) != 0 ) {
		msg(MSG_ERROR, "External command %s was not executed.", cmd);
		return 0;
	}

	/* release id */
	if (action == ACTION_DEL && opt->id_num != 0) {
		bit_array_set(&opt->ids, stat_node->id - opt->id_offset, 0);
		stat_node->id = 0;
	}

	return 1;

}

/* update statistics in node */
void update_stats(options_t *opt, unsigned int bytes, unsigned int pkts, stat_node_t *stat_node) { 

	/* lock stat_node entry */
	pthread_mutex_lock(&stat_node->lock);

	/* the node is locked - we can modify it */	
	stat_node->last_updated = time(NULL);

	stat_node->stats_bytes += bytes;
	stat_node->stats_pkts += pkts;

	if (stat_node->last_updated >= stat_node->window_reset + stat_node->window_size) {
		stat_node->window_reset = stat_node->last_updated;
		stat_node->stats_bytes = 0;
		stat_node->stats_pkts = 0;
	}

	/* unlock node */
	pthread_mutex_unlock(&stat_node->lock);
}

int eval_node(options_t *opt, stat_node_t *stat_node) { 

	int updated = 0;

	pthread_mutex_lock(&stat_node->lock);

	/* over limit */
	if (stat_node->stats_bytes / stat_node->window_size * 8 * 100 > stat_node->limit_bps * stat_node->treshold) { 
		if (stat_node->time_reported == 0) {
			exec_node_cmd(opt, stat_node, ACTION_NEW);
			updated = 1;
			pthread_mutex_lock(&opt->statistic_mutex);
			active_opt->statistic_active += 1;
			pthread_mutex_unlock(&opt->statistic_mutex);
		}
		stat_node->time_reported = stat_node->last_updated;
	/* under limit */
	} else {
		
		if (stat_node->time_reported != 0 && stat_node->time_reported + stat_node->remove_delay < stat_node->last_updated) {
			if (stat_node->last_updated >= stat_node->window_reset + stat_node->window_size) {
				exec_node_cmd(opt, stat_node, ACTION_DEL);
				updated = 1;
				pthread_mutex_lock(&opt->statistic_mutex);
				active_opt->statistic_active -= 1;
				pthread_mutex_unlock(&opt->statistic_mutex);
				stat_node->time_reported = 0;
			}
		}
	}

	pthread_mutex_unlock(&stat_node->lock);

	return updated;
}

/* pass yhrough all rules and update expired */
void dump_nodes_db(options_t *opt) { 

	stat_node_t *stat_node;
	int i = 0;
	int j = 0;
	FILE *fh;


	/* open dbdump file */
	fh = fopen(opt->dbdump_file, "w"); 

	if (fh == NULL) {
		msg(MSG_ERROR, "Can not open file %s.", opt->dbdump_file);
		return;
	}

	pthread_mutex_lock(&opt->config_mutex);
	stat_node = opt->op_root_node;

	while (stat_node != NULL) {

		stat_node_log(fh, ACTION_DUMP, opt, stat_node);
		fprintf(fh, "\n");
		i++;

		if (stat_node->time_reported != 0) {
			j++;
		}

		stat_node = stat_node->next_node;

	}

	pthread_mutex_unlock(&opt->config_mutex);
	fprintf(fh, "# total rules: %d\n", i);
	fprintf(fh, "# active rules: %d\n", j);
	fclose(fh);
}

/* pass yhrough all rules and update expired */
void update_statistic_file(options_t *opt) { 

	FILE *fh;

	if (opt->statistic_interval == 0) { 
		return;
	}

	if (opt->debug > 0) {	
		msg(MSG_DEBUG, "Updating statistic file");
	}

	/* open dbdump file */
	fh = fopen(opt->statistic_file, "w"); 

	if (fh == NULL) {
		msg(MSG_ERROR, "Can not open statistic file %s.", opt->statistic_file);
		return;
	}

	pthread_mutex_lock(&opt->statistic_mutex);
	fprintf(fh, "total rules: %d\n", opt->statistic_rules);
	fprintf(fh, "active rules: %d\n", opt->statistic_active);
	fprintf(fh, "dynamic rules: %d\n", opt->statistic_dynamic);
	fprintf(fh, "bytes: %ju\n", opt->statistic_bytes);
	fprintf(fh, "pkts: %ju\n", opt->statistic_pkts);
	pthread_mutex_unlock(&opt->statistic_mutex);
	fclose(fh);
}

/* add new dynamic node */
stat_node_t* add_dynamic_node(options_t *opt, stat_node_t *parent_node, int af, char *addr, int flow_dir, config_t config) {

	stat_node_t *new_node, *tmp;
	ip_prefix_t *ppref;

	pthread_mutex_lock(&opt->trie_mutex);	

	/* add dynamic rule */
	new_node = stat_node_new(opt, CONFIG_OP); 

	if (new_node != NULL) {

		/* copy content of the parent node except next_node pounter (assigned by stat_node_new) */
		tmp = new_node->next_node;
		memcpy(new_node, parent_node, sizeof(stat_node_t));
		new_node->next_node = tmp;

		new_node->dynamic_ipv4 = 0;
		new_node->dynamic_ipv6 = 0;
		new_node->num_prefixes = 1;

		ppref = &new_node->prefixes[0];
		ppref->af = af;
		ppref->flow_dir = flow_dir;

		if (af == AF_INET) {
			memcpy(&ppref->ip.v4, addr, sizeof(uint32_t));
			ppref->prefixlen = parent_node->dynamic_ipv4;
			addPrefixToTrie((void *)&(ppref->ip.v4), ppref->prefixlen, new_node, &opt->op_trie4[flow_dir]);
		} else {
			memcpy(&ppref->ip.v6, addr, sizeof(uint32_t[4]));
			ppref->prefixlen = parent_node->dynamic_ipv6;
			addPrefixToTrie((void *)&(ppref->ip.v6), ppref->prefixlen, new_node, &opt->op_trie6[flow_dir]);
		}

		pthread_mutex_lock(&opt->statistic_mutex);
		opt->statistic_dynamic += 1;
		pthread_mutex_unlock(&opt->statistic_mutex);

		if (opt->debug > 10) {
			msg(MSG_INFO, "Added new dynamic rule:\n");
			stat_node_log(stdout, ACTION_DUMP, opt, new_node);
			msg(MSG_INFO, "\n");
		}
	}

	pthread_mutex_unlock(&opt->trie_mutex);	

	return new_node;
}


// zpracovani IP paketu
void add_packet(options_t *opt, int af, int flow_dir, char* addr, int bytes, int pkts) {

	TTrieNode *pTn, *trie;
	stat_node_t *stat_node;

	int addrlen;


	pthread_mutex_lock(&opt->config_mutex);	

	/* detect address length */
	if (af == AF_INET) {
		addrlen = sizeof(uint32_t);
		trie = opt->op_trie4[flow_dir];
	} else {
		addrlen = sizeof(uint32_t[4]);
		trie = opt->op_trie6[flow_dir];
	}


	pthread_mutex_lock(&opt->trie_mutex);	
	pTn = lookupAddress((void *)addr, addrlen * 8, trie);
	pthread_mutex_unlock(&opt->trie_mutex);	

	if (pTn != NULL && pTn->hasValue) { 

		stat_node = pTn->Value;
		if (stat_node->dynamic_ipv4 != 0 || stat_node->dynamic_ipv6 != 0) {

			add_dynamic_node(opt, stat_node, af, addr, flow_dir, CONFIG_OP);

		} else {

			update_stats(opt, bytes, pkts, stat_node);

		}
		
	}

	pthread_mutex_unlock(&opt->config_mutex);	
}

void eval_nodes(options_t *opt) {

	int updated = 0;
	int i = 0;
	stat_node_t *stat_node;

	pthread_mutex_lock(&opt->config_mutex);
	pthread_mutex_lock(&opt->trie_mutex);

	stat_node = opt->op_root_node;

	pthread_mutex_unlock(&opt->config_mutex);
	pthread_mutex_unlock(&opt->trie_mutex);

	while (stat_node != NULL) {
		updated = eval_node(opt, stat_node);
		stat_node = stat_node->next_node;

		if (updated) { 
			i++;
		}	

		/* limit the number of updates in one step */
		if (i > UPDATES_IN_STEP) {
			return ;
		}
	}
}



// zpracovani IP paketu
inline void process_ip(const u_char *data, u_int32_t length) {

    struct ip *ip_header = (struct ip *) data; 

 //   u_int ip_header_len;
    u_int ip_total_len;
    
    ip_total_len = ntohs(ip_header->ip_len);
//    ip_header_len = ip_header->ip_hl * 4;	

	pthread_mutex_lock(&active_opt->statistic_mutex);
	active_opt->statistic_bytes += ip_total_len;
	active_opt->statistic_pkts += 1;
	pthread_mutex_unlock(&active_opt->statistic_mutex);

	add_packet(active_opt, AF_INET, FLOW_DIR_SRC, (char *)&(ip_header->ip_src.s_addr), ip_total_len, 1);
	add_packet(active_opt, AF_INET, FLOW_DIR_DST, (char *)&(ip_header->ip_dst.s_addr), ip_total_len, 1);


} // process_ip


// zpracovani ethernet paketu 
void process_eth(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {   
    u_int caplen = h->caplen; 
    struct ether_header *eth_header = (struct ether_header *) p;  // postupne orezavame hlavicky

        
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {          // je to IP protokol 
		process_ip(p + sizeof(struct ether_header), 
		   caplen - sizeof(struct ether_header));	  // predame fci pro zpracovani IP 	      
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_VLAN) {
		process_ip(p + sizeof(struct ether_header) + 4, 
		   caplen - sizeof(struct ether_header) - 4);	  // predame fci pro zpracovani IP 	      
	} 
} // konec process_eth


// Kopie zbyvajicich argumantu do rednoho retezce
char *copy_argv(char *argv[]) {
  char **arg;
  char *buf;
  int total_length = 0;

  for (arg = argv; *arg != NULL; arg++)
    total_length += (strlen(*arg) + 1); /* length of arg plus space */

  if (total_length == 0)
    return NULL;

  total_length++; /* add room for a null */

  buf = (char *)malloc(total_length);

  *buf = 0;
  for (arg = argv; *arg != NULL; arg++) {
    strcat(buf, *arg);
    strcat(buf, " ");
  }

  return buf;
}

int mkpidfile(options_t *opt) {

	FILE * fp;
	int pid;

	fp = fopen(opt->pid_file, "w");

	if (fp == NULL) {
		msg(MSG_INFO, "Can't create PID file %s (%s)", opt->pid_file, strerror(errno));
		return 0;
	}

	pid = getpid();
	fprintf(fp,"%d\n", pid);

	fclose(fp);

	return 1;

}

void listen_bpf(options_t *opt) {

//    char *expression = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];
//    struct bpf_program fcode;    // for expr

 //   expression = copy_argv(&argv[optind]);

    // try to open bpf interface 
    //if ((dev = pcap_open_live(opt.device, 68, pflag, 1100, ebuf)) == NULL) {
    if ((dev = pcap_open_live(opt->device, 68, 0, 1100, ebuf)) == NULL) {
		msg(MSG_ERROR,ebuf);
		exit(1);
    }

/*
    if (pcap_compile(dev, &fcode,  expression, 1, 0) < 0) {
        msg(MSG_ERROR, pcap_geterr(dev));
    }
	
    if (pcap_setfilter(dev, &fcode) < 0) {
		msg(MSG_ERROR, pcap_geterr(dev));
    }
*/

	msg(MSG_INFO, "Listening on %s.", opt->device);	
//	alarm(opt.expire_interval);

    if (pcap_loop(dev, -1, &process_eth, NULL) < 0) {	// start zachytavani 
		msg(MSG_ERROR, "eror");
    }  

    pcap_close(dev);

    return;
}

int main(int argc, char *argv[]) {
    extern int optind;
    char op;
//    int pflag = 0;

	pthread_t read_thread;

	options_t opt = { 
		.debug = 0, 
		.window_size = 1, 
		.remove_delay = 60, 
		.treshold = 0.8,
		.expire_interval = 60,
		.statistic_interval = 10,
		.id_num = 10000,
		.id_last = 0,
		.id_offset = 10 };


	strcpy(opt.config_file, "/etc/bwd/bwd.conf");	
	strcpy(opt.dbdump_file, "/tmp/bwd.dbdump");	
	strcpy(opt.statistic_file, "/var/run/bwd.statistics");	
	strcpy(opt.pid_file, "/var/run/bwd.pid");	
	strcpy(opt.exec_new, "/etc/bwd/bwd-new.sh");	
	strcpy(opt.exec_del, "/etc/bwd/bwd-del.sh");	
	strcpy(opt.exec_init, "/etc/bwd/bwd-init.sh");	
	strcpy(opt.exec_finish, "/etc/bwd/bwd-finish.sh");	

	pthread_mutex_init(&opt.trie_mutex, NULL);
	pthread_mutex_init(&opt.config_mutex, NULL);
	pthread_mutex_init(&opt.statistic_mutex, NULL);


    /*  process options */
	while ((op = getopt(argc, argv, "i:c:d:p:F?h")) != -1) {
		switch (op) {
			case 'i' : strncpy(opt.device,optarg, MAX_STRING); opt.device_fromarg = 1; break;
			case 'c' : strncpy(opt.config_file,optarg, MAX_STRING); break;
			case 'p' : strncpy(opt.pid_file,optarg, MAX_STRING); opt.pid_file_fromarg = 1; break;
			case 'd' : opt.debug = atoi(optarg); opt.debug_fromarg = 1; break;
			case 'F' : opt.foreground = 1; if (!opt.debug_fromarg) opt.debug = 1; break;
			case 'h' :
			case '?' : opt.debug = 1; opt.foreground = 1; msg_init(opt.debug); help(); break;
			} // konec switch op 
    } // konec while op...

	msg_init(opt.debug);

	if (opt.foreground == 0) {
		if ( !daemonize() )  {
			fprintf(stderr, "Can not daemonize process\n");
			exit(1);
		}
	}

	mkpidfile(&opt);


	if (!parse_config(&opt)) {
		exit(1);
	}

	active_opt = &opt;
    
	if ( bit_array_init(&opt.ids, opt.id_num) == NULL ) {
		msg(MSG_ERROR, "Can not ionitialise bit array\n");
		opt.id_num = 0;
	}

    signal(SIGINT, &terminates);
    signal(SIGKILL, &terminates);
    signal(SIGTERM, &terminates);
    signal(SIGUSR1, &sig_usr1);
    signal(SIGHUP, &sig_hup);

	/* bwd initialisation script */
	exec_cmd(&opt, ACTION_INIT);


	/* listen on interface */
	if ( pthread_create(&read_thread, NULL, (void *)&listen_bpf, (void *)&opt) != 0 ) {
		msg(MSG_ERROR, "Can not create read thread\n");
	}


	/* main loop */
	for (;;) {

		/* evaluate statistics and install or remove shaping rules */ 
		if (!received_term) {	
			eval_nodes(&opt);
		}

		/* update statistic file */
		if (opt.statistic_interval + opt.statistic_last < time(NULL)) {
			update_statistic_file(&opt);
			opt.statistic_last = time(NULL);
		}

		/* reaload config */
		if (!received_term && received_hup) {
			received_hup = 0;
			msg(MSG_INFO, "Request for load new configuration");
			if (!parse_config(active_opt)) {
				msg(MSG_ERROR, "Continuing with the previous configuration");
			}
		}

		/* dump nodes */
		if (!received_term && received_usr1) {
			received_usr1 = 0;
			msg(MSG_INFO, "Request for database dump.");
			dump_nodes_db(&opt);
		}

		/* terminate process */
		if (received_term) {
			//stat_node_t *stat_node;
			//int i = 0;
			received_term = 0;

			msg(MSG_INFO, "SIGTERM received. Terminating.");

			pthread_mutex_lock(&opt.config_mutex);
			pthread_mutex_lock(&opt.trie_mutex);

			exec_cmd(&opt, ACTION_FINISH);

			/* remove existing rules */
			//stat_node = active_opt->op_root_node;


			/*
			msg(MSG_INFO, "SIGTERM received. Removing installed rules (it might take while).");
			while (stat_node != NULL) {
				if ( stat_node->time_reported > 0 ) {
					exec_node_cmd(active_opt, stat_node, ACTION_DEL);
				}
				stat_node = stat_node->next_node;
				// refresh status file during removing rules  
				if (i++ > UPDATES_IN_STEP) {
					// update statistic file 
					if (opt.statistic_interval + opt.statistic_last < time(NULL)) {
						update_statistic_file(&opt);
						opt.statistic_last = time(NULL);
					}
				}
			}
			*/

//			msg(MSG_INFO, "Installed rules removed, exiting.");

			unlink(active_opt->pid_file);
			exit(0); 
		}

		/* sleep for 10 msec */
		usleep(SCAN_TIME);
	}

	return 0;
}


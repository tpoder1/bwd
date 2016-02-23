
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

pcap_t *dev;		// pouzivane rozhrani 

long last_pkt = 0;
long last_err = 0;
//long cnt = 0;
//int fl_debug = 0;
//int window = 10;	/* window size for evaluating */
//int step = 1;		/* reporting stem in Mbps */
//int drop_delay = 0;		/* wait with drop n secs */

options_t *active_opt;


void terminates(int sig) {

    struct pcap_stat stat;
	stat_node_t *stat_node;
    
    if (dev != NULL && pcap_file(dev) == NULL) 
	if (pcap_stats(dev, &stat) >= 0 && stat.ps_drop > 0) 
            msg(MSG_WARNING,"%lu packet dropped by kernel from %lu (%d%%).", 
		    stat.ps_drop, stat.ps_recv, stat.ps_drop*100/stat.ps_recv);		

	/* remove existing rules */

	stat_node = active_opt->op_root_node;

	while (stat_node != NULL) {
		if ( stat_node->time_reported > 0 ) {
			exec_node_cmd(active_opt, stat_node, ACTION_DEL);
		}
		stat_node = stat_node->next_node;
	}

	msg(MSG_INFO, "Existing rules removed, terminating");

	unlink(active_opt->pid_file);

    exit(0); 
}
    
void dump_nodes_db(options_t *opt);
void sig_usr1(int sig) {
    struct pcap_stat stat;
	msg(MSG_INFO, "Request for database dump and statistics");
    if (dev != NULL && pcap_file(dev) == NULL) 
	if (pcap_stats(dev, &stat) >= 0 && (stat.ps_drop - last_err) > 0) {
            msg(MSG_WARNING,"%lu packet dropped by kernel from %lu (%d%%).", 
		    stat.ps_drop, stat.ps_recv, stat.ps_drop*100/stat.ps_recv);

	last_pkt = stat.ps_recv - last_pkt;
	last_err = stat.ps_drop - last_err;
	}

	dump_nodes_db(active_opt);
    
//    FlowExport();
}

void sig_hup(int sig) {

	msg(MSG_INFO, "Request for load new configuration");
	if (!parse_config(active_opt)) {
		 msg(MSG_ERROR, "Continuing with the previous configuration");
	}
    
}

void check_expired_nodes(options_t *opt);
void sig_alrm(int sig) {

	check_expired_nodes(active_opt);
	alarm(active_opt->expire_interval);
	
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


void eval_node(options_t *opt, unsigned int bytes, unsigned int pkts, stat_node_t *stat_node) { 

	stat_node->last_updated = time(NULL);

	stat_node->stats_bytes += bytes;
	stat_node->stats_pkts += pkts;



	/* over limit */
	if (stat_node->stats_bytes / stat_node->window_size * 8 * 100 > stat_node->limit_bps * stat_node->treshold) { 
		if (stat_node->time_reported == 0) {
			exec_node_cmd(opt, stat_node, ACTION_NEW);
		}
		stat_node->time_reported = stat_node->last_updated;
	/* under limit */
	} else {
		
		if (stat_node->time_reported != 0 && stat_node->time_reported + stat_node->remove_delay < stat_node->last_updated) {
			if (stat_node->last_updated >= stat_node->window_reset + stat_node->window_size) {
				exec_node_cmd(opt, stat_node, ACTION_DEL);
				stat_node->time_reported = 0;
			}
		}
	}

	// reset window 
	if (stat_node->last_updated >= stat_node->window_reset + stat_node->window_size) {
		stat_node->window_reset = stat_node->last_updated;
		stat_node->stats_bytes = 0;
		stat_node->stats_pkts = 0;
	}

}

/* pass yhrough all rules and update expired */
void check_expired_nodes(options_t *opt) { 

	stat_node_t *stat_node;

	stat_node = opt->op_root_node;

	while (stat_node != NULL) {

		eval_node(opt, 0, 0, stat_node); 
		stat_node = stat_node->next_node;

	}
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

	fprintf(fh, "# total rules: %d\n", i);
	fprintf(fh, "# active rules: %d\n", j);
	fclose(fh);
}

// zpracovani IP paketu
void eval_packet(options_t *opt, int af, int flow_dir, char* addr, int bytes, int pkts) {

	TTrieNode *pTn, *trie;
	stat_node_t *stat_node, *new_node, *tmp;
	ip_prefix_t *ppref;

	int addrlen;


	/* detect address length */
	if (af == AF_INET) {
		addrlen = sizeof(uint32_t);
		trie = opt->op_trie4[flow_dir];
	} else {
		addrlen = sizeof(uint32_t[4]);
		trie = opt->op_trie6[flow_dir];
	}

	
	pTn = lookupAddress((void *)addr, addrlen * 8, trie);

	if (pTn != NULL && pTn->hasValue) { 
//		printf("Matched src record on %x\n", ip_header->ip_src.s_addr);
		stat_node = pTn->Value;
		if (stat_node->dynamic_ipv4 != 0) {

			/* add dynamic rule */
			new_node = stat_node_new(opt, CONFIG_OP); 

			if (new_node != NULL) {

				/* copy content of the parent node except next_node pounter (assigned by stat_node_new) */
				tmp = new_node->next_node;
				memcpy(new_node, stat_node, sizeof(stat_node_t));
				new_node->next_node = tmp;

				new_node->dynamic_ipv4 = 0;
				new_node->dynamic_ipv6 = 0;
				new_node->num_prefixes = 1;

				ppref = &new_node->prefixes[0];
				ppref->af = af;
				ppref->flow_dir = flow_dir;

				if (af == AF_INET) {
					memcpy(&ppref->ip.v4, addr, addrlen);
					ppref->prefixlen = stat_node->dynamic_ipv4;
					addPrefixToTrie((void *)&(ppref->ip.v4), ppref->prefixlen, new_node, &opt->op_trie4[flow_dir]);
				} else {
					memcpy(&ppref->ip.v6, addr, addrlen);
					ppref->prefixlen = stat_node->dynamic_ipv6;
					addPrefixToTrie((void *)&(ppref->ip.v6), ppref->prefixlen, new_node, &opt->op_trie6[flow_dir]);
				}

				if (opt->debug > 10) {
					msg(MSG_INFO, "Added new dynamic rule:\n");
					stat_node_log(stdout, ACTION_DUMP, opt, new_node);
					msg(MSG_INFO, "\n");
				}

				
			}

		} else {
			eval_node(opt, bytes, pkts, stat_node);
		}
		
	}
}

// zpracovani IP paketu
inline void process_ip(const u_char *data, u_int32_t length) {

    struct ip *ip_header = (struct ip *) data; 

//	stat_key_t key;
//	stat_val_t val;
//	TTrieNode *pTn;
//	stat_node_t *stat_node, *new_node;
//	ip_prefix_t *ppref;
	
    u_int ip_header_len;
    u_int ip_total_len;
    
    ip_total_len = ntohs(ip_header->ip_len);
    ip_header_len = ip_header->ip_hl * 4;	

	eval_packet(active_opt, AF_INET, FLOW_DIR_SRC, (char *)&(ip_header->ip_src.s_addr), ip_total_len, 1);
	
	eval_packet(active_opt, AF_INET, FLOW_DIR_DST, (char *)&(ip_header->ip_dst.s_addr), ip_total_len, 1);


//	printf("FLOW: %x -> %x %d \n", ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, ip_total_len);

} // konec process_ip


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

int main(int argc, char *argv[]) {
    extern int optind;
//    char *device = NULL;
    char *expression = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];
    char op;
    int pflag = 0;
    struct bpf_program fcode;    // kvuli expr

	options_t opt = { 
		.debug = 0, 
		.window_size = 1, 
		.remove_delay = 60, 
		.treshold = 0.8,
//		.expire_interval = 60 };
		.expire_interval = 60,
//		.id_num = 9,
		.id_num = 10000,
		.id_last = 0,
		.id_offset = 10 };


	strcpy(opt.config_file, "/etc/bwd/bwd.conf");	
	strcpy(opt.dbdump_file, "/tmp/bwd.dbdump");	
	strcpy(opt.pid_file, "/var/run/bwd.pid");	
	strcpy(opt.exec_new, "/etc/bwd/bwd-new.sh");	
	strcpy(opt.exec_del, "/etc/bwd/bwd-del.sh");	


    /*  process options */
	while ((op = getopt(argc, argv, "i:c:d:p:F?h")) != -1) {
		switch (op) {
			case 'i' : strncpy(opt.device,optarg, MAX_STRING); break;
			case 'c' : strncpy(opt.config_file,optarg, MAX_STRING); break;
			case 'p' : strncpy(opt.pid_file,optarg, MAX_STRING); break;
//			case 'p' : pflag = 1; break;
			case 'd' : opt.debug = atoi(optarg); break;
			case 'F' : opt.foreground = 1; break;
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

    expression = copy_argv(&argv[optind]);
          
	/* 
	if (opt.device == NULL) {			// interface nebyl zadan explicitne
		opt.device = pcap_lookupdev(ebuf);
		if (opt.device == NULL) {			// nenalezeno zadne rozhrani 
   		    msg(MSG_ERROR, ebuf);
		    exit(1);
		}					
    }
	*/
	
    //pokusime se otevrit interface
    if ((dev = pcap_open_live(opt.device, 68, pflag, 1100, ebuf)) == NULL) {
		msg(MSG_ERROR,ebuf);
		exit(1);
    }


    if (pcap_compile(dev, &fcode,  expression, 1, 0) < 0) {
        msg(MSG_ERROR, pcap_geterr(dev));
    }
	
    if (pcap_setfilter(dev, &fcode) < 0) {
		msg(MSG_ERROR, pcap_geterr(dev));
    }

    
    signal(SIGINT, &terminates);
    signal(SIGKILL, &terminates);
    signal(SIGTERM, &terminates);
    signal(SIGUSR1, &sig_usr1);
    signal(SIGALRM, &sig_alrm);
    signal(SIGHUP, &sig_hup);
	       
	msg(MSG_INFO, "Listening on %s.", opt.device);	
	alarm(opt.expire_interval);

    if (pcap_loop(dev, -1, &process_eth, NULL) < 0) {	// start zachytavani 
		msg(MSG_ERROR, "eror");
    }  

    pcap_close(dev);
    return 0;
}

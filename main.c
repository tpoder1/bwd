
#include <stdio.h>
#include "conf.h"
#include "sysdep.h"
#include "msgs.h"
#include "hash_table.h"
#include <time.h>
//#include "dataflow.h"

//#include <pcap.h>
//#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "trie.h"
//#include <netinet/tcp.h>

pcap_t *dev;		// pouzivane rozhrani 

long last_pkt = 0;
long last_err = 0;
long cnt = 0;
int fl_debug = 0;
int window = 10;	/* window size for evaluating */
int step = 1;		/* reporting stem in Mbps */
int drop_delay = 0;		/* wait with drop n secs */

hash_table_t hash_table;

TTrieNode *pTrieIPV4;

#define DIR_SRC 0x1
#define DIR_DST 0x2

typedef struct stat_key_s {
	int direction;
	uint32_t ip;
} stat_key_t;

typedef struct stat_val_s {
	long int bytes;
	long int pkts;
	int updated;
	int windowstart;
	int laststep;
	int lastrep;
} stat_val_t;


void terminates(int sig) {
    struct pcap_stat stat;
    
    if (dev != NULL && pcap_file(dev) == NULL) 
	if (pcap_stats(dev, &stat) >= 0 && stat.ps_drop > 0) 
            msg(MSG_WARMING,"%lu packet dropped by kernel from %lu (%d%%).", 
		    stat.ps_drop, stat.ps_recv, stat.ps_drop*100/stat.ps_recv);		
    exit(0); /* libpcap uses onexit to clean up */
}
    
void sig_usr1(int sig)
{
    struct pcap_stat stat;
    if (dev != NULL && pcap_file(dev) == NULL) 
	if (pcap_stats(dev, &stat) >= 0 && (stat.ps_drop - last_err) > 0) {
            msg(MSG_WARMING,"%lu packet dropped by kernel from %lu (%d%%).", 
		    stat.ps_drop, stat.ps_recv, stat.ps_drop*100/stat.ps_recv);

	last_pkt = stat.ps_recv - last_pkt;
	last_err = stat.ps_drop - last_err;
	}
    
//    FlowExport();
}


/* callback for updating items in hash table */
void aggr_callback(stat_key_t *pkey, stat_val_t *phval, stat_val_t *puval, void *data) {

	int mbps;
	char ipstr[INET6_ADDRSTRLEN] = ""; 

	// overflowed windows - zero items 
	if (phval->windowstart + window <= puval->updated) {
		mbps = 1.0 * (phval->bytes * 8) / (puval->updated - phval->windowstart) / 1000 / 1000;

		/* did we crossed last reported step */	
		if (mbps > (phval->laststep + step) ) {
			phval->laststep = mbps - (mbps % step);	/* last crossed step */
			inet_ntop(PF_INET, &pkey->ip, ipstr, sizeof(ipstr));
			printf("%c %-15s E %4d %4d\n", 
						pkey->direction == DIR_SRC ? 'S' : 'D',
						ipstr, 
						phval->laststep, mbps );

			fflush(stdout);

			phval->lastrep = puval->updated;

		} else if (mbps < phval->laststep && phval->lastrep < puval->updated - drop_delay) {

			phval->laststep = mbps - (mbps % step);	/* last crossed step */

			inet_ntop(PF_INET, &pkey->ip, ipstr, sizeof(ipstr));
			printf("%c %-15s D %4d %4d\n", 
						pkey->direction == DIR_SRC ? 'S' : 'D',
						ipstr, 
						phval->laststep + step, mbps );
			fflush(stdout);

			phval->lastrep = puval->updated;
		}

		phval->bytes = puval->bytes;
		phval->pkts = puval->pkts;
		phval->windowstart = puval->updated;
	} else {
		phval->bytes += puval->bytes;
		phval->pkts += puval->pkts;
//		printf("AGGR: %x %d %d \n", pkey->ip, phval->bytes, phval->pkts);
	}

	phval->updated = puval->updated;

}


// zpracovani IP paketu
inline void process_ip(const u_char *data, u_int32_t length) {
    struct ip *ip_header = (struct ip *) data; 

	stat_key_t key;
	stat_val_t val;
	TTrieNode *pTn;
	
    u_int ip_header_len;
    u_int ip_total_len;
    
    ip_total_len = ntohs(ip_header->ip_len);
    ip_header_len = ip_header->ip_hl * 4;	


	val.bytes = ip_total_len;
	val.pkts = 1;	
	val.updated = time(NULL);	
	val.windowstart = 0;	
	val.laststep = 0;		
	val.lastrep = 0;		

	key.ip = ip_header->ip_src.s_addr;

	pTn = lookupAddress((void *)&(key.ip), sizeof(uint32_t) * 8, pTrieIPV4);

	if (pTn != NULL && pTn->hasValue) { 
		key.direction = DIR_SRC;
		hash_table_insert_hash(&hash_table, (char *)&key, (char *)&val);
//		printf("SRC ");
	}


	key.ip = ip_header->ip_dst.s_addr;

	pTn = lookupAddress((void *)&key.ip, sizeof(uint32_t) * 8, pTrieIPV4);

	if (pTn != NULL && pTn->hasValue) { 
		key.direction = DIR_DST;		
		hash_table_insert_hash(&hash_table, (char *)&key, (char *)&val);
//		printf("DST ");
	}

//	printf("FLOW: %x -> %x %d \n", ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, ip_total_len);

} // konec process_ip


// zpracovani ethernet paketu 
inline void process_eth(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {   
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

int main(int argc, char *argv[]) {
    extern int optind;
    char *device = NULL;
    char *expression = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];
    char op;
    int oflag = 1;
    int pflag = 0;
    struct bpf_program fcode;    // kvuli expr

//    set_port("2055");		// implicitni nastaveni portu
//   set_host("127.0.0.1");	// implicitni nastaveni hosta 
//  set_maxflows("20000");	// implicitni nastaveni poctu max zaznamu 
//    set_time("300");		// implicitni nastaveni poctu sekund pro export 


    //Na zacatku zpracujeme vstupni parametry 
    while ((op = getopt(argc, argv, "i:w:s:dph:H:P:n:r:")) != -1) {
	switch (op) {
	  case 'i' : device = optarg; break;
	  case 'O' : oflag = 0; break;
	  case 'p' : pflag = 1; break;
	  case 'w' : window = atoi(optarg); break;
	  case 's' : step = atoi(optarg); break;
	  case 'r' : drop_delay = atoi(optarg); break;
	  //case 'h' : set_host(optarg); break;
	  case 'd' : fl_debug = 1; break;
	//  case 'P' : set_port(optarg); break;
	//  case 'n' : set_maxflows(optarg); break;
	//  case 'r' : set_routerid(optarg); break;
	  case '?' : help();
	} // konec switch op 
    } // konec while op...
    
    expression = copy_argv(&argv[optind]);
           
    if (device == NULL) {			// interface nebyl zadan explicitne
	device = pcap_lookupdev(ebuf);
	if (device == NULL) {			// nenalezeno zadne rozhrani 
    	    msg(MSG_ERROR, ebuf);
	    exit(1);
	}					
    }
	
    //pokusime se otevrit interface
    if ((dev = pcap_open_live(device, 68, pflag, 1100, ebuf)) == NULL) {
	msg(MSG_ERROR,ebuf);
	exit(1);
    }


    if (pcap_compile(dev, &fcode,  expression, 1, 0) < 0) {
        fprintf(stderr,pcap_geterr(dev));
    }
	
    if (pcap_setfilter(dev, &fcode) < 0) {
	 msg(MSG_ERROR, pcap_geterr(dev));
    }

//    msg(MSG_INFO, "Listening on %s.", device);	
    
//    flow_init();		// otevreni portu, alokace pameti, vycisteni pameti 

	hash_table_init(&hash_table, HASH_TABLE_INIT_SIZE, aggr_callback, NULL, NULL);
	hash_table_entry_len(&hash_table, sizeof(stat_key_t), sizeof(stat_val_t));


	/* create trie with specidied prefixes */
	{
	pTrieIPV4 = NULL;
	uint32_t pref; 
	int *pval;

	inet_aton("147.229.250.248", (void *)&pref);
	pval = malloc(sizeof(int));
	*pval = 1;

	printf("XXX %x\n", pref);
	addPrefixToTrie((void *)&pref, 16, pval, &pTrieIPV4);


	}	
           
    signal(SIGINT, &terminates);
    signal(SIGUSR1, &sig_usr1);
	       

    if (pcap_loop(dev, -1, &process_eth, NULL) < 0) {	// start zachytavani 
	msg(MSG_ERROR, "eror");
    }  

    pcap_close(dev);
    return 0;
}

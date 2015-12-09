

#include <sys/types.h>
#include <sys/socket.h>
//#include <netns/ns.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "msgs.h"
#include "dataflow.h"
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>


#define _REENTRANT

#define USLEEP_BETWEEN_UDP 350


/*************************************************************
*							     *
*   IMPLEMENTACE METOD PRO PRACI S DATOVYMI TOKY	     *
*							     *
**************************************************************/

/* Globalni promene */
pthread_t thread, tm_thread;		    // vlakno exportu 
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;     // semafor exportu 
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;	       // monitor
u_int32_t host;                     // kam se ma zasilat netflow
u_int16_t port;                     // cislo ciloveho portu
int sock;                           // handle na socket
struct sockaddr_in dst_sin;         // stktura ciloveho mista
long sequence;                      // pocet jiz exportovanych zaznamu
long datagrams;                     // pocet odeslanych datagramu
long maxflows;		    	    // max. pocet zaznamu netflow v pametu 
long ex_stime;			    // pocet sekund pro export 
short  routerid;		    // ID smerovace
struct flowitem flowtab[1];	    // staticke pole flow zaznamu 
struct flowtab flowtab1, flowtab2, *currflow;

    
/*
* prevedeni na 16b. cislo vhodne pro hash 
*/
inline unsigned int key_hash(struct FlowKey *key) {
    //struktura pro 24B -> 192b
    struct parts {
	u_int64_t p1;  // 64b
	u_int64_t p2;  // 128b 
	u_int64_t p3;  // 192b
    } *tmp; 
    u_int64_t pxor64;
    u_int32_t pxor32;
    tmp = (struct parts*)(key);    				// pretupujeme na novy zaznam 
    
    pxor64 = tmp->p1 ^ tmp->p2 ^ tmp->p3;  			// operace XOR nejdriv na 64b.
    pxor32 = (pxor64>>32 & 0xFFFFFFFF) ^ (pxor64 & 0xFFFFFFFF); // a nyni na 32b.
    return (pxor32>>16 & 0xFFFF)<<4 ^ (pxor32 & 0xFFFF);	// na zaver na 16b.
} 


/*
* test zda jsou klice totozne 
*/
inline int key_eq(struct FlowKey *key1, struct FlowKey *key2) {
    //struktura pro 24B -> 192b
    struct parts {
	u_int64_t p1;  // 64b
	u_int64_t p2;  // 128b 
	u_int64_t p3;  // 192b
    } *tmp1, *tmp2;
    tmp1 = (struct parts*)(key1);    // pretupujeme na novy zaznam 
    tmp2 = (struct parts*)(key2);
    // a provedeme porovnani. Diky zkracenemu vyhodnocovani vyrazu koncime pri prvni neshode        
    return (tmp1->p1 == tmp2->p1) && (tmp1->p2 == tmp2->p2) && (tmp1->p2 == tmp2->p2);
} 


/*
* vynulovani klice
*/
inline void key_clean(struct FlowKey *key) {
    //struktura pro 24B -> 192b
    struct parts {
	u_int64_t p1;  // 64b
	u_int64_t p2;  // 128b 
	u_int64_t p3;  // 192b
    } *tmp;
    tmp = (struct parts*)(key);    	// pretupujeme na novy zaznam 
    
    tmp->p1 = 0x0000000000000000;	// a zkopirujeme jednotlive plozky 
    tmp->p2 = 0x0000000000000000;
    tmp->p3 = 0x0000000000000000;
} 


/*
* kopie klice 
*/
inline void key_cp(struct FlowKey *key1, struct FlowKey *key2) {
    //struktura pro 24B -> 192b
    struct parts {
	u_int64_t p1;  // 64b
	u_int64_t p2;  // 128b 
	u_int64_t p3;  // 192b
    } *tmp1, *tmp2;
    tmp1 = (struct parts*)(key1);    	// pretupujeme na novy zaznam 
    tmp2 = (struct parts*)(key2);
    
    tmp2->p1 = tmp1->p1;	// a zkopirujeme jednotlive plozky 
    tmp2->p2 = tmp1->p2;
    tmp2->p3 = tmp1->p3;
} 


/*
* vycisteni pameti pro jeden flow 
*/
inline void flow_clean(struct flowtab *flow) {
    /* vycisteni pameti */
    int x;
    for (x = 0; x < HASH_SIZE + 1; x++) {
	flow->hashidx[x] = NULL;
    }
    
    /* a tabulky s flow zaznamy */
    for (x = 0; x < maxflows + 1; x++) {
	key_clean(&(flow->items[x].key));
    }
    flow->counter = 0;
}



/*
* nastaveni cisla portu
*/
void set_port(char* xport) {
    long tmpport;
    if ((tmpport = atoi(xport)) < 0) {
	msg(MSG_ERROR,"Invalid port value (%s).",port);
	exit(1);
    }
    port = htons(tmpport);
}


/*
* pro kolik zaznamu se ma alokovat pamet ? 
*/
void set_maxflows(char* xsize) {
    int tmpsize;
    if ((tmpsize = atoi(xsize)) < 1000) {
	msg(MSG_ERROR,"Invalid flows count value (%s). Allowed 1001 - 1000000", xsize);
	exit(1);
    }
    maxflows = tmpsize;
}


/*
* nastaveni hosta (vcetne prevedeni IP adresy na cilo)
*/
void set_host(char* xhost) {
    if ((host = inet_addr(xhost)) == 0xffffffff) {
	msg(MSG_ERROR,"Invalid host adress (%s).",xhost);
	exit(1);
    }
    msg(MSG_DEBUG, "HOST: %x\n", host); 
}


/*
* nastaveni pctu sekund pro export 
*/
void set_time(char* xtime) {
    if ((ex_stime = atoi(xtime)) < 10) {
	msg(MSG_ERROR,"Invalid export time (%s). Allowed 10-30000 seconds.",xtime);
	exit(1);
    }
}

/*
* nastaveni ID smerovace
*/
void set_routerid(char* xrouter) {
    if ((routerid = atoi(xrouter)) < 0 || routerid > 255) {
	msg(MSG_ERROR,"Invalid router ID (%s). Allowed 0-255.",xrouter);
	exit(1);
    }
}


/*
* odeslani UDP paketu s 30 zaznamy a hlavickou 
*/
inline void send_export(struct FlowHead5 *flow, int count) {    
    int errcode;
    time_t currtime;
    
    currtime = time(NULL);
        
    flow->version = htons(5);                     // Current version=5
    flow->count = htons(count);                       // The number of records in PDU.
    flow->SysUptime = htonl(currtime);            // Current time in msecs since router booted
    flow->unix_secs = htonl(currtime);            // Current seconds since 0000 UTC 1970
    flow->unix_nsecs = htonl(0);           // Residual nanoseconds since 0000 UTC 1970
    flow->flow_sequence = htonl(sequence);        // Sequence number of total flows seen
    sequence = sequence + count;
    flow->engine_type = 0x0;          // Type of flow switching engine (RP,VIP,etc.)
    flow->engine_id = flow->engine_id = routerid;            // Slot number of the flow switching engine
    flow->reserved = htons(0);            // zeros

    errcode = sendto(sock, (char*)flow, 
	        sizeof(struct FlowHead5),
		0, (struct sockaddr*)&dst_sin, sizeof(struct sockaddr));

    usleep(USLEEP_BETWEEN_UDP);	    
    while (errcode < 0) {
	usleep(USLEEP_BETWEEN_UDP);
	msg(MSG_DEBUG, "Buffer underflow");
        errcode = sendto(sock, (char*)flow, 
		    sizeof(struct FlowHead5),
		    0, (struct sockaddr*)&dst_sin, sizeof(struct sockaddr));
    }
}


/*
* nacteni dat z fronty a volani SendExport pro odelani UDP paketu
* volano na sigalrm 
*/
void flow_change(int sig) {
    
    if (currflow == &flowtab1) {// zmena aktualniho hashe pro ukladani flow 
	currflow = &flowtab2; 	// musi resit stejne vlakno, ktere resi zapisy
    } else { 			// jinak muze nastat konflikt (v pripade zmeny pri
	currflow = &flowtab1; 	// provadeni flow_add
    }

    // uvolneni semaforu 
    pthread_cond_signal(&cond);	// uvolneni cekani waid na druhem vlakne 
    alarm(ex_stime);		// nastaveni dalsiho exportu 
}

/* 
* export UDP datagramu - v nekonecne smycce spousteno minitorem 
*/
void *flow_export(void *arg) {
    struct FlowHead5 head;
    struct flowitem *flptr;	// ukazatel z hashe na tabulku hodnot  
    long cnt = 0;		// celkovy pocet exportovanych zaznamu 
    long pkts = 0;		// celkovy pocet exportovanych paketu 
    long bts = 0;		// celkovy pocet exportovanych b
    long datagrams = 0;		// vynulovani poctu odeslanych datagramu 
    int pos = 0;		// indikator nasplneni plneho poctu pro jeden UDP paket
    long x;

    struct flowtab *wrkflow;	// uklozime se flo do ktereho jsme doted cpali data
    
    pthread_mutex_lock(&mutex);
    
    for(;;) {	
	pthread_cond_wait(&cond, &mutex);	//cekani na signal 
	
	cnt = 0;		// vynylovani pocitadel  
	pkts = 0; 
	bts = 0;
	datagrams = 0;
	pos = 0;
	
	
	if (currflow == &flowtab1) {	// zjisteni prave neaktualniho flow
	    wrkflow = &flowtab2; 	
	} else { 			
    	    wrkflow = &flowtab1; 
	}

	msg(MSG_DEBUG, "Starting export");

	for (x = 0; x < (wrkflow->counter); x++) {		// pruchod vsemi zaznamy
	    flptr = &(wrkflow->items[x]);
	    //naplnime strukturu pro netflow
	    head.items[pos].srcaddr = flptr->key.srcaddr;
	    head.items[pos].dstaddr = flptr->key.dstaddr;
	    head.items[pos].srcport = flptr->key.srcport;
	    head.items[pos].dstport = flptr->key.dstport;
	    head.items[pos].tcp_flags = flptr->key.tcp_flags;
	    head.items[pos].prot = flptr->key.prot;
	    head.items[pos].dPkts = htonl(flptr->val.dPkts);
	    head.items[pos].dOctets = htonl(flptr->val.dOctets);
	    head.items[pos].input = htons(1);
	    head.items[pos].output = htons(255);		
	    if (pos == EXPORT_COUNT - 1) {  		// jiz mame dost zaznamu pro odeslani UDP paketu
		send_export(&head, pos + 1); 
		pos = 0;
		datagrams++;
	    } else { pos++; }
	    cnt++;
	    pkts += flptr->val.dPkts;
	    bts += flptr->val.dOctets;
	    flptr++;
	}    
    
	if (pos > 0) {					// a jeste odesleme zbyvajici data
	    send_export(&head, pos + 1);
	    datagrams++;
	}
    
	flow_clean(wrkflow);				// uklidime po sobe 

	msg(MSG_DEBUG, "Exported %d records (%d sum packets, %d sum bytes, %d UDP datagrams).", 
		cnt, pkts, bts, datagrams);
    }
    
    return NULL;
}

/*
* inicializace
* - vytvoreni socketu na adresu a port, inicializace poli + jejich vynulovani 
*/
void flow_init() {
    
    struct sockaddr_in src_sin;
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    dst_sin.sin_family = AF_INET;
    dst_sin.sin_addr.s_addr = host;
    dst_sin.sin_port = port;

    src_sin.sin_family = AF_INET;
    src_sin.sin_addr.s_addr = INADDR_ANY;
    src_sin.sin_port = 0;
    bind(sock, (struct sockaddr*)&src_sin, sizeof(struct sockaddr_in));

    /* alokace pameti */
    flowtab1.items = (struct flowitem*)malloc(maxflows * sizeof(struct flowitem) + 1);    
    flowtab2.items = (struct flowitem*)malloc(maxflows * sizeof(struct flowitem) + 1);    
        
    /* vyciteni hash table */
    flow_clean(&flowtab1);
    flow_clean(&flowtab2);
    currflow = &flowtab1;   // aktivni flow, ktery budeme pouzivat 
    
    /* nastaveni casu pro export */
    signal(SIGALRM, &flow_change);
    alarm(ex_stime);
    
    /* vytvireni vlakna pro exporty flow */
    if (pthread_create(&thread, NULL, flow_export, NULL) != 0) {
        msg(MSG_ERROR, "Pthread_create error");
    }		  
}


/*
* varti pointer na dalsi volny zaznam v tabulce flowtab
*/
inline struct flowitem*  get_next() {
    return (&currflow->items[currflow->counter++]);
}

/*
* test zda neni uz tabulka plna. Pokud ano je zamenen currflow a je dan pokyn k exportu 
*/
inline void table_free() {
    if (currflow->counter < maxflows) return;	/* vse je zatim OK */
    flow_change(0);				/* tabulka uz je plna -> exportujem */
}


/*
* vlozeni jednoho zaznamu o datovem toku
*/
inline void flow_add(struct FlowKey *key, long bytes, long pkts) {    
    struct flowitem *hashptr, *lastptr = NULL;	// ukazatel z hashe na tabulku hodnot  
    u_int16_t hash;				// hodnota hashe
        
    table_free();				// test zda neni tabulka jiz plna 
    
    hash = key_hash(key);			// zjisteni hashe (XOR)
    hashptr = currflow->hashidx[hash];		// zjisteni pozice do flotable kde ukazuje hash 
    
    if (hashptr == NULL) {			// prvni zaznam na pozici key
	hashptr = get_next();			// zjistime prvni volny zaznam v flowtable 
						// (z drivejka mame zajisteno, ze tabulka neni plna)
	currflow->hashidx[hash] = hashptr;	// ulozime do hashtable odkaz na nas zaznam 
	key_cp(key, &(hashptr->key));		// a zapiseme hodnoty 
	hashptr->val.dPkts = pkts;
	hashptr->val.dOctets = bytes;
	hashptr->next = NULL;
	return ;
    } else {					// skoda, v tabulce uz je zaznam. Musime projit seznamem a popripade pridat dalsi 
	while (hashptr != NULL) {
	    if (key_eq(key, &hashptr->key)) {	// bezva - hodnoty klice si odpovidaji 
		hashptr->val.dPkts += pkts;	// takze pouze pricteme nove hodnoty 
		hashptr->val.dOctets += bytes;
		return;				// a ukoncime cele pridavani 
	    } else {				// zaznamy si neodpovidaji (konflikt) - musime hledat dal 
		lastptr = hashptr;		// ulozime si pointer predposledniho zaznamu 
		hashptr = hashptr->next;	// dalsi zaznam v seznamu 
	    }
	} 					// while
    }

    // predchozi cyklus nebyl ukoncem returnem to znamena, ze
    // zaznam s odpovidajici si hodnotou klicu neexistuje
    // nezbyva tedy nez jej pridat na konec seznamu 

    lastptr->next = get_next();			// ziskame dalsi volnou pozici ve flowtable
    hashptr = lastptr->next;			// pro jednoduchost si ptr zkopirujeme 
    key_cp(key, &(hashptr->key));		// a zapiseme hodnoty 
    hashptr->val.dPkts = pkts;
    hashptr->val.dOctets = bytes;
    hashptr->next = NULL;
    
} // konec AddFlow



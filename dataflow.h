
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define EXPORT_COUNT 30			// pocet zaznamu NetFlow na jeden UDP datagram 
#define HASH_SIZE 4*65535*2		// velikost staticke hash tabulky



// flow record within a version 5 NetFlow Export datagram
struct FlowItem5 {
    u_int32_t srcaddr;			// Source IP Address
    u_int32_t dstaddr;			// Destination IP Address
    u_int32_t nexthop;			// Next hop router's IP Address
    unsigned short input;		// Input interface index
    unsigned short output;		// Output interface index

    unsigned long dPkts;		// Packets sent in Duration (milliseconds between
					// 1st & last packet in  this flow)
    unsigned long dOctets;		// Octets sent in Duration (milliseconds between
		        		// 1st & last packet in this flow)
    unsigned long First;		// SysUptime at start of flow
    unsigned long Last;			// and of last packet of the flow
    unsigned short srcport;		// TCP/UDP source port number (.e.g, FTP, Telnet,
					// etc.,or equivalent)
    unsigned short dstport;		// TCP/UDP destination port number (.e.g, FTP,
					// Telnet, etc.,or equivalent)
    unsigned char pad1;			// pad to word boundary
    unsigned char tcp_flags;		// Cumulative OR of tcp flags
    unsigned char prot;			// IP protocol, e.g., 6=TCP, 17=UDP, etc...
    unsigned char tos;			// IP Type-of-Service
    unsigned short dst_as;		// dst peer/origin Autonomous System
    unsigned short src_as;		// source peer/origin Autonomous System
    unsigned char dst_mask;		// destination route's mask bits
    unsigned char src_mask;		// source route's mask bits
    unsigned short pad2;		// pad to word boundary
};


// NetFlow Export Version 5 Header Format
struct FlowHead5 {
    unsigned short version;		// Current version=5
    unsigned short count;		// The number of records in PDU.
    unsigned long SysUptime;		// Current time in msecs since router booted
    unsigned long unix_secs;		// Current seconds since 0000 UTC 1970
    unsigned long unix_nsecs;		// Residual nanoseconds since 0000 UTC 1970
    unsigned long flow_sequence;	// Sequence number of total flows seen
    unsigned char engine_type;		// Type of flow switching engine (RP,VIP,etc.)
    unsigned char engine_id;		// Slot number of the flow switching engine
    unsigned short reserved;		// zeros
    struct FlowItem5 items[EXPORT_COUNT];	// zaznamy
};


// klic pro ukladani do hashe
struct FlowKey  {
    u_int32_t srcaddr;			// 32 Source IP Address
    u_int32_t dstaddr;			// 32 Destination IP Address
    u_int32_t nexthop;			// 32 Next hop router's IP Address
    unsigned short input;		// 16 Input interface index
    unsigned short output;		// 16 Output interface index
    unsigned short srcport;		// 16 TCP/UDP source port number (.e.g, FTP, Telnet,
					//    etc.,or equivalent)
    unsigned short dstport;		// 16 TCP/UDP destination port number (.e.g, FTP,
					//    Telnet, etc.,or equivalent)
    unsigned char tcp_flags;		//  8 Cumulative OR of tcp flags
    unsigned char prot;			//  8 IP protocol, e.g., 6=TCP, 17=UDP, etc...
    unsigned char dst_mask;		//  8 destination route's mask bits
    unsigned char src_mask;		//  8 source route's mask bits
					// celkem 192b -> 24B
};

// hodnoty ke klici v hashi 
struct FlowVal  {
    unsigned long dPkts;		// Packets sent in Duration (milliseconds between
					// 1st & last packet in  this flow)
    unsigned long dOctets;		// Octets sent in Duration (milliseconds between
		        		// 1st & last packet in this flow)
};

struct flowitem {                   // struktura zaznamu v hashovaci tabulce
        struct FlowKey key;         // hodnota
        struct FlowVal val;         // hodnotu paktu a bajtu
        struct flowitem *next;      // pripadny pointer na dalsi zaznam
    }; 

struct flowtab {
        struct flowitem *hashidx[HASH_SIZE + 1];// pole pro prevod XOR hash -> poiter na zaznam do flowtable
        struct flowitem *items;                 // tabulka zaznamu
        long counter;                           // pocet zaznamu v tabulce
    };


inline unsigned int key_hash(struct FlowKey *key);
inline int key_eq(struct FlowKey *key1, struct FlowKey *key2);
inline void key_clean(struct FlowKey *key);
inline void key_cp(struct FlowKey *key1, struct FlowKey *key2);
inline void flow_clean(struct flowtab *flow);
void set_port(char* xport);
void set_maxflows(char* xsize);
void set_host(char* xhost);
void set_time(char* xtime);
void set_routerid(char* xrouter);
inline void send_export(struct FlowHead5 *flow, int count);
void flow_change(int sig);
void *flow_export(void *arg);
void flow_init();
inline struct flowitem*  get_next();
inline void table_free();
inline void flow_add(struct FlowKey *key, long bytes, long pkts);


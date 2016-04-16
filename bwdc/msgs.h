

#define MSG_ERROR 1
#define MSG_WARNING 2
#define MSG_DEBUG 3
#define MSG_INFO 4


void msg_init(int debug);
void msg(int type, char* msg, ...);
void help();


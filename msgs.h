
#define FLOW_VERSION "0.92"

#define MSG_ERROR 1
#define MSG_WARMING 2
#define MSG_DEBUG 3
#define MSG_INFO 4

void msg(int type, char* msg, ...);
void help();

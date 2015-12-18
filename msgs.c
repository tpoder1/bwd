

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include "bwd.h"

int log_debug = 0;

/***************************************************
*             HLESENI CHYB                         *
****************************************************/

void msg_init(int debug) {

	log_debug = debug;

	openlog(LOG_NAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

}


void msg(int type, char* msg, ...) {

//    if (type != MSG_DEBUG || debug) {
	va_list arg;
	int level;
	char buf[MAX_STRING];

	if (!log_debug && type == LOG_DEBUG) {
		return;	
	}

	switch (type) {
		case MSG_ERROR: 	level = LOG_ERR; break;
		case MSG_WARNING: 	level = LOG_WARNING; break;
		case MSG_DEBUG:		level = LOG_DEBUG; break; 
		default:			level = LOG_INFO; break;
	}

	va_start(arg, msg);
	vsnprintf(buf, MAX_STRING - 1, msg, arg);
	va_end(arg);

	if (log_debug) {
		printf("%s\n", buf);
	}
	syslog(level, "%s", buf);
    
}

/*
* help
*/
void help() {
    msg(MSG_INFO, "Welcome traffic analyses %s", LOG_VERSION);
    msg(MSG_INFO, "Comment please send to <tpoder@cis.vutbr.cz>");
    msg(MSG_INFO, "");
    msg(MSG_INFO, "Usage: trafscan [-i <interface>] [-p] [ -w windows size ] [ -s step size ] [ -r drop ignore ]  ");
    msg(MSG_INFO, "               [-t <time period>] [<expression>]"); 
    msg(MSG_INFO, ""); 
    msg(MSG_INFO, "-i <interface>   Listen on interface."); 
    msg(MSG_INFO, "-p               Put the interface into promiscuous mode."); 
    msg(MSG_INFO, "<expression>     Same expression as in tcpdump. See man tcpdump."); 
    msg(MSG_INFO, ""); 
    exit(0);
}

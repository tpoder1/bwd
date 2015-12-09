

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "msgs.h"

int debug = 0;

/***************************************************
*             HLESENI CHYB                         *
****************************************************/


void msg(int type, char* msg, ...) {

//    if (type != MSG_DEBUG || debug) {
	va_list arg;
    
	va_start(arg, msg);
	vprintf( msg, arg);
	printf("\n");
	va_end(arg);
//    }
    
}

/*
* napoveda k prikazu
*/
void help() {
    msg(MSG_INFO, "Welcome traffic analyses %s", FLOW_VERSION);
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

/* 

 Copyright (c) 2013-2015, Tomas Podermanski
    
 This file is part of libnf.net project.

 Libnf is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Libnf is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with libnf.  If not, see <http://www.gnu.org/licenses/>.

*/

%defines
%pure-parser
%lex-param   { yyscan_t scanner }
%lex-param	 { options_t *opt }
%parse-param { yyscan_t scanner }
%parse-param { options_t *opt }

%{
	#include <stdio.h>
	#include "bwd.h"
	#include <string.h>
//	#include "ffilter.h"
//	#include "ffilter_internal.h"

	#define YY_EXTRA_TYPE options_t

//	int ff2_lex();

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

#ifndef YY_TYPEDEF_YY_BUFFER_STATE
#define YY_TYPEDEF_YY_BUFFER_STATE
typedef struct yy_buffer_state *YY_BUFFER_STATE;
#endif

	#define MAX_STRING 1024

	//void yyerror(yyscan_t scanner, ff_t *filter, char *msg) {
	void yyerror(yyscan_t scanner, options_t *opt, char *errmsg) {

		msg(MSG_ERROR, "config file: %s (line: %d)\n", errmsg, yyget_lineno(scanner) );
//		ff_set_error(filter, msg);
	}


%}

%union {
	long int	number;	
	char 		string[1024];
	char 		ipv4[1024];
	char 		ipv6[1024];
	void		*node;
	stat_node_t	*stat_node;
};

%token OBRACE EBRACE SLASH SEMICOLON
%token RULETOK LIMITTOK SRCTOK DSTTOK IPTOK 
%token DYNAMICTOK IPV4TOK IPV6TOK BITPSTOK PPSTOK
%token IFACETOK OPTIONSTOK DBDUMPTOK DEBUGTOK FILETOK
%token LEVELTOK COMMANDTOK NEWTOK DELTOK TRESHOLDTOK 
%token WINDOWTOK SIZETOK EXPIRETOK DELAYTOK IDTOK OFFSETTOK
%token <number> NUMBER FACTOR
%token <ipv4> IPV4ADDR 
%token <ipv6> IPV6ADDR
%token <string> STRING
%type <stat_node> rule rules ruleparam ruleparams 
/* %type <string> options optionparams option */

%%

config: /* empty */
	options rules
	;

options: /* empty */
	OPTIONSTOK OBRACE optionparams EBRACE; 
	;

optionparams: /* empty */ 
	| optionparams option SEMICOLON;
	;

option:
	| IFACETOK STRING 				{ strncpy(opt->device, $2, MAX_STRING); }
	| DEBUGTOK LEVELTOK NUMBER 		{ opt->debug = $3; }
	| DBDUMPTOK FILETOK STRING 		{ strncpy(opt->dbdump_file, $3, MAX_STRING); }
	| NEWTOK COMMANDTOK STRING 		{ strncpy(opt->exec_new, $3, MAX_STRING); }
	| DELTOK COMMANDTOK STRING 		{ strncpy(opt->exec_del, $3, MAX_STRING); }
	| TRESHOLDTOK NUMBER 			{ opt->treshold = $2; }
	| WINDOWTOK SIZETOK NUMBER 		{ opt->window_size = $3; }
	| EXPIRETOK DELAYTOK NUMBER 	{ opt->expire_interval = $3; }
	| DELTOK DELAYTOK NUMBER 		{ opt->remove_delay = $3; opt->expire_interval = $3; }
	| IDTOK OFFSETTOK NUMBER 		{ opt->id_offset = $3; }
	;

rules: /* empty */
	| rules rule;

rule: 
	RULETOK OBRACE { $<stat_node>$ = stat_node_new(opt); if ($<stat_node>$ == NULL) { YYABORT; }; } ruleparams EBRACE	{ ;  } 
	;

ruleparams: /* empty */ 
	| ruleparams { $<stat_node>$ = $<stat_node>0; } ruleparam SEMICOLON;
	;


ruleparam:
	| LIMITTOK NUMBER FACTOR BITPSTOK 		{ $<stat_node>0->limit_bps = $2 * $3; }
	| LIMITTOK NUMBER BITPSTOK 				{ $<stat_node>0->limit_bps = $2; }
	| LIMITTOK NUMBER FACTOR PPSTOK 		{ $<stat_node>0->limit_pps = $2 * $3; }
	| LIMITTOK NUMBER PPSTOK 				{ $<stat_node>0->limit_pps = $2; }
	| DYNAMICTOK IPV4TOK NUMBER 			{ if ($3 <= 32 )  { $<stat_node>0->dynamic_ipv4 = $3; } }
	| DYNAMICTOK IPV6TOK NUMBER 			{ if ($3 <= 128 ) { $<stat_node>0->dynamic_ipv6 = $3; } }
	| SRCTOK IPTOK IPV4ADDR 				{ if ( !stat_node_add(opt, AF_INET, FLOW_DIR_SRC, $3, 32, $<stat_node>0) ) { YYABORT; }  ; }
	| SRCTOK IPTOK IPV6ADDR 				{ if ( !stat_node_add(opt, AF_INET6, FLOW_DIR_SRC, $3, 128, $<stat_node>0) ) { YYABORT; }  ; }
	| SRCTOK IPTOK IPV4ADDR SLASH NUMBER 	{ if ( !stat_node_add(opt, AF_INET, FLOW_DIR_SRC, $3, $5, $<stat_node>0) ) { YYABORT; }  ; }
	| SRCTOK IPTOK IPV6ADDR SLASH NUMBER 	{ if ( !stat_node_add(opt, AF_INET6, FLOW_DIR_SRC, $3, $5, $<stat_node>0) ) { YYABORT; }  ; }
	| DSTTOK IPTOK IPV4ADDR 				{ if ( !stat_node_add(opt, AF_INET, FLOW_DIR_DST, $3, 32, $<stat_node>0) ) { YYABORT; }  ; }
	| DSTTOK IPTOK IPV6ADDR 				{ if ( !stat_node_add(opt, AF_INET6, FLOW_DIR_DST, $3, 128, $<stat_node>0) ) { YYABORT; }  ; }
	| DSTTOK IPTOK IPV4ADDR SLASH NUMBER 	{ if ( !stat_node_add(opt, AF_INET, FLOW_DIR_DST, $3, $5, $<stat_node>0) ) { YYABORT; }  ; }
	| DSTTOK IPTOK IPV6ADDR SLASH NUMBER 	{ if ( !stat_node_add(opt, AF_INET6, FLOW_DIR_DST, $3, $5, $<stat_node>0) ) { YYABORT; }  ; }
	; 
%% 

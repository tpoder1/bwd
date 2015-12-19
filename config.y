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

		msg(MSG_ERROR, "config file: %s\n", errmsg);
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
%token DYNAMICTOK IPV4TOK IPV6TOK
%token <number> NUMBER
%token <ipv4> IPV4ADDR 
%token <ipv6> IPV6ADDR
%type <stat_node> rule rules ruleparam ruleparams 


%%

config: /* empty */
	| rules;
	;

rules: /* empty */
	| rules rule;

rule: 
	RULETOK OBRACE { $<stat_node>$ = stat_node_new(opt); if ($<stat_node>$ == NULL) { YYABORT; }; } ruleparams EBRACE	{ stat_node_log(opt, $<stat_node>3); } 
	;

ruleparams: /* empty */ 
	| ruleparams { $<stat_node>$ = $<stat_node>0; } ruleparam SEMICOLON;
	;

ruleparam:
	| LIMITTOK NUMBER  						{ $<stat_node>0->limit_bps = $2; }
	| DYNAMICTOK IPV4TOK NUMBER 			{ $<stat_node>0->dynamic_ipv4 = $3; }
	| DYNAMICTOK IPV6TOK NUMBER 			{ $<stat_node>0->dynamic_ipv6 = $3; }
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

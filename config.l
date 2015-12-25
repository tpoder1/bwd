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

%option outfile="lex.yy.c"
%option reentrant bison-bridge
%option noyywrap 
%option nounput
%option noinput
%option yylineno

%{
	#include <stdlib.h>
	#include <string.h>
	#include "bwd.h"
	#include "config.tab.h"
%}

%%
#.*				{ ; }	// comments 
\"(.+)\"			{
					strncpy(yylval->string, yytext + 1, MAX_STRING - 1);
					yylval->string[yyleng - 2] = '\0';
					return STRING;
				}
\{				return OBRACE;
\}				return EBRACE;
;				return SEMICOLON;
options			return OPTIONSTOK; 
interface		return IFACETOK; 
dbdump			return DBDUMPTOK; 
file			return FILETOK; 
debug			return DEBUGTOK; 
level			return LEVELTOK; 
command			return COMMANDTOK; 
new				return NEWTOK; 
del				return DELTOK; 
treshold		return TRESHOLDTOK; 
window			return WINDOWTOK; 
size			return SIZETOK; 
expire			return EXPIRETOK; 
delay			return DELAYTOK; 
id				return IDTOK; 
offset			return OFFSETTOK; 
rule			return RULETOK; 
limit			return LIMITTOK; 
src				return SRCTOK; 
dst				return DSTTOK;
ip				return IPTOK; 
ipv4			return IPV4TOK; 
ipv6			return IPV6TOK; 
dynamic			return DYNAMICTOK; 
bps				return BITPSTOK; 
b\/s			return BITPSTOK; 
pps				return PPSTOK; 
p\/s			return PPSTOK; 
\/				return SLASH;
[K|k]			{
					yylval->number = 1000;
					return FACTOR;
				}
[M|m]			{
					yylval->number = 1000 * 1000;
					return FACTOR;
				}
[0-9]+			{
					yylval->number = atoi(yytext);
					return NUMBER;
				}
[0-9\.]{7,15}	{
					strncpy(yylval->string, yytext, MAX_STRING - 1);
					return IPV4ADDR;
				}
[0-9a-fA-F\.\:]{9,39}	{
					strncpy(yylval->string, yytext, MAX_STRING - 1);
					return IPV6ADDR;
				}
\n				{ ; } 	// ignore EOL 
[ \t]+			{ ; } 	// ignore whitespace 
%%


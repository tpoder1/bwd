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

%{
	#include <stdlib.h>
	#include <string.h>
	#include "bwd.h"
	#include "config.tab.h"
%}

%%
#.*				{ ; }	// comments 
\{				return OBRACE;
\}				return EBRACE;
;				return SEMICOLON;
rule			return RULETOK; 
limit			return LIMITTOK; 
src				return SRCTOK; 
dst				return DSTTOK;
ip				return IPTOK; 
\/				return SLASH;
[0-9]+			{
					yylval->number = atoi(yytext);
					return NUMBER;
				}
[0-9\.]{7,15}	{
					strncpy(yylval->string, yytext, MAX_STRING - 1);
					return IPV4ADDR;
				}
[0-9\.\:]{9,15}	{
					strncpy(yylval->string, yytext, MAX_STRING - 1);
					return IPV6ADDR;
				}
\n				{ ; } 	// ignore EOL 
[ \t]+			{ ; } 	// ignore whitespace 
%%


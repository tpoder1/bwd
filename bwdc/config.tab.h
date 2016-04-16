/* A Bison parser, made by GNU Bison 2.7.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2012 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YY_CONFIG_TAB_H_INCLUDED
# define YY_YY_CONFIG_TAB_H_INCLUDED
/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     OBRACE = 258,
     EBRACE = 259,
     SLASH = 260,
     SEMICOLON = 261,
     RULETOK = 262,
     LIMITTOK = 263,
     SRCTOK = 264,
     DSTTOK = 265,
     IPTOK = 266,
     DYNAMICTOK = 267,
     IPV4TOK = 268,
     IPV6TOK = 269,
     BITPSTOK = 270,
     PPSTOK = 271,
     IFACETOK = 272,
     OPTIONSTOK = 273,
     DBDUMPTOK = 274,
     DEBUGTOK = 275,
     FILETOK = 276,
     LEVELTOK = 277,
     COMMANDTOK = 278,
     NEWTOK = 279,
     DELTOK = 280,
     TRESHOLDTOK = 281,
     WINDOWTOK = 282,
     SIZETOK = 283,
     EXPIRETOK = 284,
     DELAYTOK = 285,
     IDTOK = 286,
     OFFSETTOK = 287,
     PIDTOK = 288,
     STATISTICTOK = 289,
     NUMBER = 290,
     FACTOR = 291,
     IPV4ADDR = 292,
     IPV6ADDR = 293,
     STRING = 294
   };
#endif


#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{
/* Line 2058 of yacc.c  */
#line 62 "config.y"

	long int	number;	
	char 		string[1024];
	char 		ipv4[1024];
	char 		ipv6[1024];
	void		*node;
	stat_node_t	*stat_node;


/* Line 2058 of yacc.c  */
#line 106 "config.tab.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (yyscan_t scanner, options_t *opt);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */

#endif /* !YY_YY_CONFIG_TAB_H_INCLUDED  */

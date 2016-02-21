
distdir = bwd

main:
	lex config.l
	bison -d config.y
	gcc -O3 msgs.c main.c hash_table.c xxhash.c trie.c lex.yy.c config.tab.c config.c bit_array.c daemonize.c -lpcap -pthread -Wall \
	    -L/usr/local/lib/ \
	    -o bwd

clean:
	rm netflow

dist:  
	mkdir $(distdir)
	cp -R Makefile README conf.h main.c dataflow.* msgs.* sysdep.h $(distdir)
	find $(distdir) -name .svn -delete
	tar czf $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)


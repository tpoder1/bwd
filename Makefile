
distdir = trafscan

main:
	gcc -O3 msgs.c main.c hash_table.c xxhash.c trie.c -lpcap -pthread -Wall -finline-functions \
	    -L/usr/local/lib/ \
	    -o trafscan

clean:
	rm netflow

dist:  
	mkdir $(distdir)
	cp -R Makefile README conf.h main.c dataflow.* msgs.* sysdep.h $(distdir)
	find $(distdir) -name .svn -delete
	tar czf $(distdir).tar.gz $(distdir)
	rm -rf $(distdir)


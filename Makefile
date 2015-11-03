CFLAGS=-O3
LDFLAGS=-lodp -lodphelper -lm
CC=gcc

l2fwd_clf: main.c pc.c hash_lkup.c
	$(CC) $(CFLAGS) main.c pc.c hash_lkup.c -o $@ $(LDFLAGS)

clean:
	rm -f *.o l2fwd_clf

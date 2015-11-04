CFLAGS=-O3
LDFLAGS=-lodp -lodphelper -lm
CC=gcc
OBJ=main.o pc.o hash_lkup.o sub

l2fwd_clf: $(OBJ)
	$(CC) $(CFLAGS) main.o pc.o hash_lkup.o ./ac/sm_builder.o ./ac/acsmx.o ./ac/acsmx2.o ./ac/bnfa_search.o ./ac/util.o -o $@ $(LDFLAGS)

.PHONY: sub
sub:
	$(MAKE) -C ./ac

clean:
	rm -f *.o l2fwd_clf
	rm -f ./ac/*.o


AC_SUB_OBJS := $(AC_OBJ:ac/%=%)

$(AC_SUB_OBJS): %.o : %.c
	$(CC) $(CFLAGS) $(INCLUDE_FILES) -c $< -o $@ $(LIBS)

#sm_builder.o:
#	$(CC) $(CFLAGS) $(INCLUDE_FILES) -c sm_builder.c -o $@ $(LIBS)
#
#acsmx.o:
#	$(CC) $(CFLAGS) $(INCLUDE_FILES) -c acsmx.c -o $@ $(LIBS)
#
#acsmx2.o:
#	$(CC) $(CFLAGS) $(INCLUDE_FILES) -c acsmx2.c -o $@ $(LIBS)
#
#util.o:
#	$(CC) $(CFLAGS) $(INCLUDE_FILES) -c util.c -o $@ $(LIBS)
#
#bnfa_search.o:
#	$(CC) $(CFLAGS) $(INCLUDE_FILES) -c bnfa_search.c -o $@ $(LIBS)



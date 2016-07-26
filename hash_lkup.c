#include "hash_lkup.h"

#include <odp.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


odph_table_t create_hash_table(void)
{
    odph_table_t hash_table;
    hash_table = odph_cuckoo_table_create("OCC_HASH_TABLE", HASH_ENTRIES, FIVE_TUPLE_LEN, 1);
    if (hash_table == NULL) {
        fprintf(stderr, "hash table create failed!\n");
        exit(-1);
    }
    int i;
    uint32_t ft[5];
    char tag = VALUE_TAG;
    for (i = 0; i < HASH_ENTRIES; i++) {
        ft[0] = ft[1] = ft[2] = ft[3] = ft[4] = i;
        if (odph_cuckoo_table_put_value(hash_table, ft, &tag) == -1) {
            fprintf(stderr, "hash table insert failed on %d!\n", i);
        }
    }

#if 0
    void *k, *v;
    uint32_t next;
    int ret;
    do {
        ret = odph_cuckoo_table_iterate(hash_table, &k, &v, &next);
        printf("%u %c\n",((uint32_t*)k)[0], *((char*)v));
    } while(ret != -1);
#endif

    return hash_table;
}

int odph_hash_lookup(odph_table_t ht, void *key) {
    char buf;
    return odph_cuckoo_table_get_value(ht, key, &buf, 1);
}

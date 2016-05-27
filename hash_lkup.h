#ifndef HASH_LOOK_UP_H
#define HASH_LOOK_UP_H

#include <odph_cuckootable.h>

#define HASH_ENTRIES 1000000
#define FIVE_TUPLE_LEN 20
#define VALUE_LEN 1
#define VALUE_TAG 'Y'

odph_table_t create_hash_table(void);
int odph_hash_lookup(odph_table_t, void*);

#endif

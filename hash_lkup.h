#ifndef HASH_LOOK_UP_H
#define HASH_LOOK_UP_H


#include <odp/helper/hash.h>

#define HASH_ENTRIES 100000
#define FIVE_TUPLE_LEN 20

typedef struct odph_hash *odph_hash_t;
typedef struct odph_hash_parameters odph_hash_param_t;

void hash_env_init();

odph_hash_t create_hash_table(void);

#endif

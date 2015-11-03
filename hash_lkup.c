#include "hash_lkup.h"

#include <odp.h>
#include <odp/helper/ring.h>
#include <odp/helper/hash_jhash.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void hash_env_init()
{
    odph_hash_list_init();
    odph_ring_tailq_init();
}

odph_hash_t create_hash_table(void)
{
    odph_hash_t hdl;
    odph_hash_param_t param;
    memset(&param, 0, sizeof(param));
    param.name = "L2FWD";
    param.entries = HASH_ENTRIES;
    param.key_len = FIVE_TUPLE_LEN;
    param.hash_func = odph_jhash;
    param.hash_func_init_val = 0x1234;
    hdl = odph_hash_create(&param);

    if(hdl == NULL)
    {
        return NULL;
    }

    uint32_t i;
    uint32_t ft[5];
    int ret;
    for(i = 0; i < HASH_ENTRIES; i++)
    {
        ft[0] = ft[1] = ft[2] = ft[3] = ft[4] = i;
        ret = odph_hash_add_key(hdl, (void*)ft);
        if(ret == -EINVAL)
        {
            fprintf(stderr, "add key %u failure!\n", i);
        }
    }

    return hdl;
}

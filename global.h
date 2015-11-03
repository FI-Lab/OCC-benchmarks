#ifndef GLOBAL_H
#define GLOBAL_H

#include <odp.h>
#include <odp/helper/linux.h>

#define NIC_NAME_MAX_LEN 64
#define REGULAR_FILE_NAME_MAX_LEN 256

typedef struct global_param_s
{
    struct
    {
        int num;
        char names[ODP_CONFIG_PKTIO_ENTRIES][NIC_NAME_MAX_LEN];
    }nic;

    odp_cpumask_t cpu_mask;

    char rule_file[REGULAR_FILE_NAME_MAX_LEN];
    char fib_file[REGULAR_FILE_NAME_MAX_LEN];
    
}global_param_t;

typedef struct thread_data_s
{
    odp_pktio_t nic_hdl[ODP_CONFIG_PKTIO_ENTRIES];
    odph_linux_pthread_t thr_tbl[ODP_CONFIG_PKTIO_ENTRIES];
}thread_data_t;

#define PACKET_POOL_MAX_ELT_NUM 4096
#define PACKET_POOL_OBJ_SZ 2048

#define PACKET_IO_BURST 32

typedef struct port_stat_s
{
    struct
    {
        uint64_t recv;
        uint64_t send;
        uint64_t drop;
    }stat[ODP_CONFIG_PKTIO_ENTRIES];
}port_stat_t;

#endif

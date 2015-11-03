#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <odp.h>
#include <odp/helper/linux.h>
#include <odp/helper/udp.h>
#include <odp/helper/ip.h>

#include "global.h"
#include "pc.h"
#include "hash_lkup.h"

#define EXECUTE_HASH_LOOKUP
#define EXECUTE_CLASSIFICATION

/***************************/
global_param_t glb_param;

void usage()
{
    printf("Usage: l2fwd_clf -i <interface1,interface2,....> -r <rule set> -l <fib>\n");
}

void parse_ifs(char *str)
{
    char *s, *sp, *tok[ODP_CONFIG_PKTIO_ENTRIES];
    int i;
    for(i = 0, s = str;;)
    {
        tok[i] = strtok_r(s, ",", &sp);
        s = NULL;
        if(tok[i] == NULL)
        {
            break;
        }
        memcpy(glb_param.nic.names[i], tok[i], strlen(tok[i]) + 1);
        i++;
    }
    glb_param.nic.num = i;
}

void parse_param(int argc, char **argv)
{
    int ch;
    while((ch = getopt(argc, argv, "i:r:l:k:")) != -1)
    {
        switch(ch)
        {
            case 'i':
                parse_ifs(optarg);
    
                //1:1 thread:nic
                int i;
                odp_cpumask_zero(&glb_param.cpu_mask);
                for(i = 0; i < glb_param.nic.num; i++)
                {
                    odp_cpumask_set(&glb_param.cpu_mask, i);
                }
                break;
            case 'r':
                memcpy(glb_param.rule_file, optarg, strlen(optarg) + 1);
                break;
            case 'l':
                memcpy(glb_param.fib_file, optarg, strlen(optarg) + 1);
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }
}

/***********************/
odp_pool_t create_pkt_pool(char *name, uint32_t obj_sz, uint32_t elt_num)
{
    odp_pool_param_t param;
    odp_pool_t pool;
    memset(&param, 0, sizeof(param));
    param.type = ODP_POOL_PACKET;
    param.pkt.num = elt_num;
    param.pkt.len = obj_sz;
    param.pkt.seg_len = obj_sz;
    pool = odp_pool_create(name, &param);
    return pool;
}

/***********************/
thread_data_t thr_data;
port_stat_t port_stat;

odph_hash_t hs_tbl;

int init_all_if(odp_pool_t pkt_pool)
{
    odp_pktio_param_t param;
    odp_pktio_t hdl;
    int i;
    uint8_t mac[6];
    uint32_t mtu;

    param.in_mode = ODP_PKTIN_MODE_RECV;
    param.out_mode = ODP_PKTOUT_MODE_SEND;

    for(i = 0; i < glb_param.nic.num; i++)
    {
        hdl = odp_pktio_open(glb_param.nic.names[i], pkt_pool, &param);
        if(hdl == ODP_PKTIO_INVALID)
        {
            return -1;
        }
        if(odp_pktio_mac_addr(hdl, mac, 6) < 0)
        {
            return -1;
        }
        if((mtu = odp_pktio_mtu(hdl)) < 0)
        {
            return -1;
        }
        if(odp_pktio_promisc_mode_set(hdl, 1) < 0)
        {
            return -1;
        }
        if(odp_pktio_start(hdl) < 0)
        {
            return -1;
        }
        thr_data.nic_hdl[i] = hdl;
        printf("NIC: %s (MAC:%2x-%2x-%2x-%2x-%2x-%2x, MTU:%u)\n",
                glb_param.nic.names[i],
                mac[0], mac[1], mac[2],
                mac[3], mac[4], mac[5],
                mtu);
    }
    return 0;
}

/***********************/
int extract_tuple(odp_packet_t pkt, uint32_t ft[5])
{
    odph_ipv4hdr_t *ip;
    odph_udphdr_t *udp;
    ip = (odph_ipv4hdr_t*)odp_packet_l3_ptr(pkt, NULL);
    if(ip == NULL)
    {
        fprintf(stderr, "recv an invalid packet(is not ip packet)!\n");
        return -1;
    }
    udp = (odph_udphdr_t*)odp_packet_l4_ptr(pkt, NULL);
    if(udp == NULL)
    {
        fprintf(stderr, "recv an invalid packet(is not tcp/udp packet)!\n");
        return -1;
    }
    ft[0] = ntohl(ip->src_addr);
    ft[1] = ntohl(ip->dst_addr);
    ft[2] = ntohs(udp->src_port);
    ft[3] = ntohs(udp->dst_port);
    ft[4] = ip->proto;
    return 0;
}

/***********************/
void* thread_fwd_routine(void *arg)
{
    odp_packet_t pkt_tbl[PACKET_IO_BURST];
    int rv_nb, sd_nb;
    int thr_id;
    int out_port;
    int tuple[5];
    int i;

    thr_id = odp_thread_id();
    printf("fwd thread %d start(on cpu %d)\n", thr_id, odp_cpu_id());
    //match to port id
    thr_id--;

    memset(&port_stat.stat[thr_id], 0 , 3 * sizeof(uint64_t));
    for(;;)
    {
        rv_nb = odp_pktio_recv(thr_data.nic_hdl[thr_id], pkt_tbl, 
                PACKET_IO_BURST);
        port_stat.stat[thr_id].recv += rv_nb;
#ifdef EXECUTE_CLASSIFICATION
        for(i = 0; i < rv_nb; i++)
        {
            if(extract_tuple(pkt_tbl[i], tuple) == 0)
            {
                int res;
                res = packet_classifier_search(tuple);
            }
        }
#endif
#ifdef EXECUTE_HASH_LOOKUP
        for(i = 0; i < rv_nb; i++)
        {
            if(extract_tuple(pkt_tbl[i], tuple) == 0)
            {
                int res;
                res = odph_hash_lookup(hs_tbl, (void*)tuple);
            }
        }
#endif
        if((thr_id & 1) == 1)
        {
            out_port = thr_id - 1;
        }
        else
        {
            out_port = thr_id + 1 == glb_param.nic.num ? thr_id : thr_id + 1;
        }
        sd_nb = odp_pktio_send(thr_data.nic_hdl[out_port], pkt_tbl, rv_nb);
        port_stat.stat[thr_id].send += sd_nb;
        while(sd_nb < rv_nb)
        {
            odp_packet_free(pkt_tbl[sd_nb++]);
            port_stat.stat[thr_id].drop++;
        }
    }
    return NULL;
}


/***********************/

void* thread_stat_routine(void *arg)
{
    int i;
    while(1)
    {
        sleep(5);
        i = system("clear");
        printf("Port statistics(on cpu %d)\n", odp_cpu_id());
        for(i = 0; i < glb_param.nic.num; i++)
        {
            printf("Port %d:\n", i);
            printf(">>>>>>>>recv: %llu\n", (unsigned long long)port_stat.stat[i].recv);
            printf(">>>>>>>>send: %llu\n", (unsigned long long)port_stat.stat[i].send);
            printf(">>>>>>>>drop: %llu\n", (unsigned long long)port_stat.stat[i].drop);
            printf("====================\n");
        }
    }
}

int main(int argc, char **argv)
{
    int ret;
    ret = odp_init_global(NULL, NULL);
    if(ret < 0)
    {
        fprintf(stderr, "global init failure!\n");
        exit(EXIT_FAILURE);
    }
    ret = odp_init_local(ODP_THREAD_CONTROL);
    if(ret < 0)
    {
        fprintf(stderr, "local init failure!\n");
        exit(EXIT_FAILURE);
    }

    parse_param(argc, argv);

    packet_classifier_init(glb_param.rule_file, glb_param.fib_file);
    hash_env_init();

    hs_tbl = create_hash_table();

    odp_pool_t pkt_pool;
    pkt_pool = create_pkt_pool("PACKET_POOL",PACKET_POOL_OBJ_SZ,
            PACKET_POOL_MAX_ELT_NUM);
    if(pkt_pool == ODP_POOL_INVALID)
    {
        fprintf(stderr, "create packet pool failure!\n");
        exit(EXIT_FAILURE);
    }

    if(init_all_if(pkt_pool) == -1)
    {
        fprintf(stderr, "init nic faliure!\n");
        exit(EXIT_FAILURE);
    }
    
    odph_linux_pthread_t thr_tbl[ODP_CONFIG_PKTIO_ENTRIES];
    int thr_num;
    thr_num = odph_linux_pthread_create(thr_tbl, &glb_param.cpu_mask, thread_fwd_routine, NULL);
    if(thr_num != glb_param.nic.num)
    {
        fprintf(stderr, "some nic thread start failure!\n");
        exit(EXIT_FAILURE);
    }

    odph_linux_pthread_t thr_stat_hdl;
    odp_cpumask_t thr_stat_mask;
    
    odp_cpumask_zero(&thr_stat_mask);
    odp_cpumask_set(&thr_stat_mask, glb_param.nic.num);
    if(odph_linux_pthread_create(&thr_stat_hdl, &thr_stat_mask, thread_stat_routine, NULL) != 1)
    {
        fprintf(stderr, "stat thread start failure!\n");
        exit(EXIT_FAILURE);
    }

    odph_linux_pthread_join(thr_tbl, thr_num);
    odph_linux_pthread_join(&thr_stat_hdl, 1);
 

    int nic_id;
    for(nic_id = 0; nic_id < glb_param.nic.num; nic_id++)
    {
        odp_pktio_close(thr_data.nic_hdl[nic_id]);
    }
    odph_hash_free(hs_tbl);
    odp_pool_destroy(pkt_pool);

    odp_term_local();
    odp_term_global();

    return 0;
}

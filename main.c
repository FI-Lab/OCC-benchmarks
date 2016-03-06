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
#include <odp/helper/tcp.h>
#include <odp/helper/eth.h>

#include "global.h"
#include "pc.h"
#include "hash_lkup.h"

#include "ac/sm_builder.h"

//#define EXECUTE_CRC
//#define EXECUTE_HASH_LOOKUP
//#define EXECUTE_CLASSIFICATION
#define EXECUTE_DPI

#define BUF_SIZE 2048
#define NB_BUF 8000

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
            case 'k':
                memcpy(glb_param.pat_file, optarg, strlen(optarg) + 1);
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
    param.pkt.seg_len = PACKET_SEG_LEN;
    pool = odp_pool_create(name, &param);
    return pool;
}

/***********************/
thread_data_t thr_data;
port_stat_t port_stat;

odph_hash_t hs_tbl;
sm_hdl_t *sm_hdl;

int init_all_if()
{
    odp_pktio_t hdl;
    odp_pool_t pkt_pool;
    int i;
    uint8_t mac[6];
    uint32_t mtu;
    char pool_name[20];

    for(i = 0; i < glb_param.nic.num; i++)
    {
        snprintf(pool_name, 20, "%s_pool", glb_param.nic.names[i]);
        pkt_pool = create_pkt_pool(pool_name, BUF_SIZE, NB_BUF);
        if(pkt_pool == ODP_POOL_INVALID)
        {
            return -1;
        }
        hdl = odp_pktio_open(glb_param.nic.names[i], pkt_pool);
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
        //if(odp_pktio_start(hdl) < 0)
        //{
        //    return -1;
        //}
        thr_data.nic_hdl[i] = hdl;
        printf("NIC: %s (MAC:%2x-%2x-%2x-%2x-%2x-%2x, MTU:%u)\n",
                glb_param.nic.names[i],
                mac[0], mac[1], mac[2],
                mac[3], mac[4], mac[5],
                mtu);
        struct odp_pktio_eth_link link;
        odp_pktio_link_get(hdl, &link);
        printf("iface %s %s\n", glb_param.nic.names[i], link.link_status == 1 ? "up" : "down");
    }
    return 0;
}

/***********************/
int extract_tuple(odp_packet_t pkt, uint32_t ft[5])
{
    odph_ipv4hdr_t *ip;
    odph_udphdr_t *udp;
    char *data = odp_packet_data(pkt);
    ip = (odph_ipv4hdr_t*)(data + sizeof(odph_ethhdr_t));
    if(ip == NULL)
    {
        fprintf(stderr, "recv an invalid packet(is not ip packet)!\n");
        return -1;
    }
    udp = (odph_udphdr_t*)((char*)ip + sizeof(odph_ipv4hdr_t));
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


int get_payload(odp_packet_t pkt, unsigned char **payload, int *len)
{
    odph_ipv4hdr_t *ip;
    int payload_offset;
    char *data = odp_packet_data(pkt);
    ip = (odph_ipv4hdr_t*)(data + sizeof(odph_ethhdr_t));
    if(ip == NULL)
    {
        fprintf(stderr, "recv non-ip packet!\n");
        return -1;
    }
    payload_offset = (ip->ver_ihl & 0xf) << 2;
    if(ip->proto == 6)//TCP
    {
        odph_tcphdr_t *tcp;
        tcp = (odph_tcphdr_t*)((char*)ip + sizeof(odph_ipv4hdr_t));
        //printf("%d\n", (tcp->hl & 0xf) << 2);
        payload_offset += (tcp->hl & 0xf) << 2;
        *len = ntohs(ip->tot_len) - payload_offset;
        *payload = (unsigned char*)ip + payload_offset;
        //printf("payload %s\n", (char*)*payload);
        //printf("len %d\n", *len);
        return 0;
    }
    else if(ip->proto == 17)
    {
        payload_offset += 8;
        *len = ntohs(ip->tot_len) - payload_offset;
        *payload = (unsigned char*)ip + payload_offset;
        return 0;
    }
    fprintf(stderr, "recv non-tcp/udp packet!\n");
    return -1;
}

static void calc_chk_sum(odp_packet_t m)
{
    uint8_t sum;
    uint32_t i;
    odph_ipv4hdr_t *ip;
    uint32_t len;
    uint8_t *pkt = (uint8_t*)odp_packet_data(m);
    ip = (odph_ipv4hdr_t*)(odp_packet_data(m) + sizeof(odph_ethhdr_t));
    len = ntohs(ip->tot_len) + sizeof(odph_ethhdr_t);
    for(i = 0, sum = 0; i < len; i++)
    {
        sum += pkt[i];
    }
    pkt[i-1] = sum;
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
    thr_id = odp_cpu_id();
    printf("fwd thread %d start(on cpu %d)\n", odp_thread_id(), odp_cpu_id());
    //match to port id

    memset(&port_stat.stat[thr_id], 0 , 3 * sizeof(uint64_t));
    for(;;)
    {
        rv_nb = odp_pktio_recv(thr_data.nic_hdl[thr_id], pkt_tbl, 
                PACKET_IO_BURST);
        port_stat.stat[thr_id].recv += rv_nb;
#ifdef EXECUTE_CRC
        for(i = 0; i < rv_nb; i++)
        {
            calc_chk_sum(pkt_tbl[i]);
        }
#endif
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
#ifdef EXECUTE_DPI
        unsigned char *payload;
        int payload_len;
        for(i = 0; i < rv_nb; i++)
        {
            if(get_payload(pkt_tbl[i], (unsigned char**)&payload, &payload_len) == 0)
            {
                int res;
                //printf("%d %d %s\n", thr_id, strlen(payload), payload);
                res = sm_search(sm_hdl, payload, payload_len);
                //printf("search res: %d\n", res);
            }
        }
#endif
        /*if((thr_id & 1) == 1)
          {
          out_port = thr_id - 1;
          }
          else
          {
          out_port = thr_id + 1 == glb_param.nic.num ? thr_id : thr_id + 1;
          }*/
        out_port = thr_id;
        char smac[6];
        if(odp_pktio_mac_addr(thr_data.nic_hdl[out_port], smac, 6) < 0)
        {
            fprintf(stderr, "cpu %d get port mac addr failed!\n", thr_id);
            exit(-1);
        }
        for(i = 0; i < rv_nb; i++)
        {
            odph_ethhdr_t *eth = (odph_ethhdr_t*)odp_packet_data(pkt_tbl[i]);
            memcpy(eth->dst.addr, eth->src.addr, 6);
            memcpy(eth->src.addr, smac, 6);
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
    sm_hdl = sm_build(glb_param.pat_file);

    hs_tbl = create_hash_table();

    if(init_all_if() == -1)
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
    sm_destroy(sm_hdl);
    odph_hash_free(hs_tbl);

    odp_term_local();
    odp_term_global();

    return 0;
}

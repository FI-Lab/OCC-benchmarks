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
#include <signal.h>

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

//#define USED_CC
#define CC_LOW 0
#define CC_HIGH 8
//#define EXECUTE_CRC
//#define EXECUTE_HASH_LOOKUP
#define EXECUTE_CLASSIFICATION
//#define EXECUTE_DPI

//#define D02_MQ_MODE
//#define EXECUTE_BUF_CNT

#define BUF_SIZE 1856
#define NB_BUF 4000

/*control variable*/
int is_stop = 0;

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
    odp_pool_param_init(&param);
    param.type = ODP_POOL_PACKET;
    param.pkt.num = elt_num;
    param.pkt.len = obj_sz;
    param.pkt.seg_len = obj_sz;
#ifndef USED_CC
    pool = odp_pool_create(name, &param);
#else
    param.colors.start = CC_LOW;
    param.colors.end = CC_HIGH;
    pool = odp_pool_create_cc(name, &param);
#endif
    return pool;
}

/***********************/
thread_data_t thr_data;
port_stat_t port_stat;

odph_table_t hs_tbl;
sm_hdl_t *sm_hdl;

int init_all_if()
{
    odp_pktio_t hdl;
    odp_pool_t pkt_pool;
    int i;
    uint8_t mac[6];
    uint32_t mtu;
    char pool_name[20];
    odp_pktio_param_t  param;
    odp_pktin_queue_param_t inq_param;
    odp_pktout_queue_param_t outq_param;

    for(i = 0; i < glb_param.nic.num; i++)
    {
        snprintf(pool_name, 20, "%s_pool", glb_param.nic.names[i]);
        pkt_pool = create_pkt_pool(pool_name, BUF_SIZE, NB_BUF);
        if(pkt_pool == ODP_POOL_INVALID)
        {
            return -1;
        }
        odp_pool_print(pkt_pool);

        odp_pktio_param_init(&param);
        param.in_mode = ODP_PKTIN_MODE_DIRECT;
        param.out_mode = ODP_PKTOUT_MODE_DIRECT;

        hdl = odp_pktio_open(glb_param.nic.names[i], pkt_pool, &param);
        if(hdl == ODP_PKTIO_INVALID)
        {
            return -1;
        }
        odp_pktin_queue_param_init(&inq_param);
        odp_pktout_queue_param_init(&outq_param);
        inq_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
        inq_param.hash_enable = 1;
        inq_param.hash_proto.proto.ipv4_udp = 1;
        inq_param.num_queues = 1;
        
        if(odp_pktin_queue_config(hdl, &inq_param)) {
            fprintf(stderr, "pktin queue config failed!\n");
            return -1;
        }
    
        outq_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
        outq_param.num_queues = 1;
        if(odp_pktout_queue_config(hdl, &outq_param)) {
            fprintf(stderr, "pktout queue config failed!\n");
            return -1;
        }

        if(odp_pktin_queue(hdl, &thr_data.in_q[i], 1) != 1) {
            fprintf(stderr, "acquire pktin queue failed!\n");
            return -1;
        }

        if(odp_pktout_queue(hdl, &thr_data.out_q[i], 1) != 1) {
            fprintf(stderr, "acquire pktout queue failed!\n");
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
        /*if(odp_pktio_promisc_mode_set(hdl, 1) < 0)
        {
            return -1;
        }*/
        if(odp_pktio_start(hdl) < 0)
        {
            return -1;
        }
#ifdef EXECUTE_BUF_CNT
        thr_data.pa_ht[i] = odph_cuckoo_table_create(pool_name, NB_BUF << 1, sizeof(uint64_t), sizeof(uint64_t));
        if(thr_data.pa_ht[i] == NULL) {
            fprintf(stderr, "pa hash table create failed in %d if!\n", i);
            return -1;
        }
#endif
        thr_data.nic_hdl[i] = hdl;
        printf("NIC: %s (MAC:%02x-%02x-%02x-%02x-%02x-%02x, MTU:%u)\n",
                glb_param.nic.names[i],
                mac[0], mac[1], mac[2],
                mac[3], mac[4], mac[5],
                mtu);
        //struct odp_pktio_eth_link link;
        //odp_pktio_link_get(hdl, &link);
        printf("iface %s %s\n", glb_param.nic.names[i], odp_pktio_link_status(hdl) == 1 ? "up" : odp_pktio_link_status(hdl) == 0 ? "down" : "failed");
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

    odp_pktio_t pktio = thr_data.nic_hdl[thr_id];
    odp_pktin_queue_t inq = thr_data.in_q[thr_id];
    odp_pktout_queue_t outq = thr_data.out_q[thr_id];
#ifdef EXECUTE_BUF_CNT
    odph_table_t pa_ht = thr_data.pa_ht[thr_id];
#endif

    printf("inq %llx %d, outq %llx %d\n", (unsigned long long)inq.pktio, inq.index, (unsigned long long)outq.pktio, outq.index);

    memset(&port_stat.stat[thr_id], 0 , 3 * sizeof(uint64_t));

    int find_queue = 0;
    while (!is_stop)
    {
#ifndef D02_MQ_MODE
        rv_nb = odp_pktio_recv(pktio, pkt_tbl, PACKET_IO_BURST);
#else
        rv_nb = odp_pktio_recv_queue(inq, pkt_tbl, 
                PACKET_IO_BURST);
        inq.index = inq.index >= 15 ? 0 : inq.index + 1;
#endif
        /*if(rv_nb > 0) {
            find_queue = 1;
        } else {
            if(!find_queue) {
                inq.index = inq.index >= 15 ? 0 : inq.index + 1;
            }
            continue;
        }*/
        if (rv_nb <= 0) {
            continue;
        }

#ifdef EXECUTE_BUF_CNT
        for(i = 0; i < rv_nb; i++) {
            odp_packet_seg_t seg = odp_packet_first_seg(pkt_tbl[i]);
            uint64_t paddr = (uint64_t)odp_v2p((void*)seg);
            uint64_t counter;
            if(odph_cuckoo_table_get_value(pa_ht, &paddr, &counter, sizeof(counter)) == -1) {
                counter = 1;
            } else {
                counter++;
            }
            if(odph_cuckoo_table_put_value(pa_ht, &paddr, &counter) == -1) {
                fprintf(stderr, "thr %d put pa %llx (%lld) failed!\n", thr_id, (unsigned long long)paddr, (unsigned long long)counter);
            }
        }
#endif

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
#ifndef D02_MQ_MODE
        sd_nb = odp_pktio_send(pktio, pkt_tbl, rv_nb);
#else
        sd_nb = odp_pktio_send_queue(outq, pkt_tbl, rv_nb);
#endif
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
    while (!is_stop)
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

#ifdef EXECUTE_BUF_CNT
static void sig_hdl(int sig) {
    is_stop = 1;
    printf("sigint executed by cpu %d\n", odp_cpu_id());
}

static void write_pa() {
    
}
#endif
/**/


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
#ifdef EXECUTE_BUF_CNT
    signal(SIGUSR1, sig_hdl);
#endif

    parse_param(argc, argv);

    packet_classifier_init(glb_param.rule_file, glb_param.fib_file);
    //hash_env_init();
    sm_hdl = sm_build(glb_param.pat_file);

    hs_tbl = create_hash_table();

    if(init_all_if() == -1)
    {
        fprintf(stderr, "init nic faliure!\n");
        exit(EXIT_FAILURE);
    }

    odph_linux_pthread_t thr_tbl[ODP_CONFIG_PKTIO_ENTRIES];
    int thr_num;
    thr_num = odph_linux_pthread_create(thr_tbl, &glb_param.cpu_mask, thread_fwd_routine, NULL, ODP_THREAD_WORKER);
    if(thr_num != glb_param.nic.num)
    {
        fprintf(stderr, "some nic thread start failure!\n");
        exit(EXIT_FAILURE);
    }

    odph_linux_pthread_t thr_stat_hdl;
    odp_cpumask_t thr_stat_mask;

    odp_cpumask_zero(&thr_stat_mask);
    odp_cpumask_set(&thr_stat_mask, glb_param.nic.num);
    if(odph_linux_pthread_create(&thr_stat_hdl, &thr_stat_mask, thread_stat_routine, NULL, ODP_THREAD_WORKER) != 1)
    {
        fprintf(stderr, "stat thread start failure!\n");
        exit(EXIT_FAILURE);
    }

    odph_linux_pthread_join(thr_tbl, thr_num);
    odph_linux_pthread_join(&thr_stat_hdl, 1);

#ifdef EXECUTE_BUF_CNT
    write_pa();
#endif

    int nic_id;
    for(nic_id = 0; nic_id < glb_param.nic.num; nic_id++)
    {
        odp_pktio_close(thr_data.nic_hdl[nic_id]);
    }
    sm_destroy(sm_hdl);
    odph_cuckoo_table_destroy(hs_tbl);

    odp_term_local();
    odp_term_global();

    return 0;
}

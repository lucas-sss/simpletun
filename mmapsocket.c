#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

struct block_desc
{
    uint32_t version;
    uint32_t offset_to_priv;
    struct tpacket_hdr_v1 h1;
};

struct ring
{
    struct iovec *rd;
    uint8_t *map;
    struct tpacket_req3 req;
};

static unsigned long packets_total = 0, bytes_total = 0;
static sig_atomic_t sigint = 0;

static void sighandler(int num)
{
    sigint = 1;
}

/* 初始化套接字，包括套接口创建、接收缓冲区的创建等 */
static int setup_socket(struct ring *ring, char *netdev)
{
    printf("setup_socket -> netdev: %s\n", netdev);

    int err, i, fd, v = TPACKET_V3;
    struct sockaddr_ll ll;
    unsigned int blocksiz = 1 << 17, framesiz = 1 << 11;
    unsigned int blocknum = 64;
    int fanout_arg;

    /* 创建套接口 */
    // fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0)
    {
        perror("socket");
        exit(1);
    }

    /* 设置PACKET版本，有v1、v2和v3三个版本，默认是v1 */
    err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (err < 0)
    {
        perror("setsockopt");
        exit(1);
    }

    memset(&ring->req, 0, sizeof(ring->req));
    ring->req.tp_block_size = blocksiz;
    ring->req.tp_frame_size = framesiz;
    ring->req.tp_block_nr = blocknum;
    ring->req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
    ring->req.tp_retire_blk_tov = 60;
    ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    /* 创建ringBuf */
    // err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req, sizeof(ring->req));
    err = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &ring->req, sizeof(ring->req));
    if (err < 0)
    {
        perror("setsockopt");
        exit(1);
    }

    /* 将ringBuf映射到用户态 */
    // ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
    ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring->map == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }

    /* 使用iovec向量的方式来访问缓冲区，为每个块创建一个向量，存储到ring->rd中 */
    ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
    assert(ring->rd);
    /* 初始化向量，使用与每个块对应 */
    for (i = 0; i < ring->req.tp_block_nr; ++i)
    {
        ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
        ring->rd[i].iov_len = ring->req.tp_block_size;
    }

    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    // ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex = if_nametoindex(netdev);
    ll.sll_hatype = 0;
    ll.sll_pkttype = 0;
    ll.sll_halen = 0;

    /* 将这个原始套接字绑定到某个网口（netdev） */
    err = bind(fd, (struct sockaddr *)&ll, sizeof(ll));
    if (err < 0)
    {
        perror("bind");
        exit(1);
    }

    return fd;
}

/* 显示报文数据 */
static void display(struct tpacket3_hdr *ppd)
{
    unsigned char sip[4];
    unsigned char dip[4];
    unsigned char *buffer;
    size_t datalen = 0;

    // printf("display\n");

    buffer = (uint8_t *)ppd + ppd->tp_mac;
    datalen = (size_t)ppd->tp_len;

    memcpy(sip, &buffer[12], 4);
    memcpy(dip, &buffer[16], 4);
    // printf("read tun data: %d.%d.%d.%d -> %d.%d.%d.%d (%d)\n", dip[0], dip[1], dip[2], dip[3], sip[0], sip[1], sip[2], sip[3], datalen);

    /* 帧头部的地址加上MAC偏移量，就是以太网报文的地址 */
    struct ethhdr *eth = (struct ethhdr *)((uint8_t *)ppd + ppd->tp_mac);
    struct iphdr *ip = (struct iphdr *)((uint8_t *)eth + ETH_HLEN);
    if (eth->h_proto == htons(ETH_P_IP))
    {
        struct sockaddr_in ss, sd;
        char sbuff[1024], dbuff[1024];

        memset(&ss, 0, sizeof(ss));
        ss.sin_family = PF_INET;
        ss.sin_addr.s_addr = ip->saddr;
        /* 将源IP地址转换成主机名字 */
        getnameinfo((struct sockaddr *)&ss, sizeof(ss), sbuff, sizeof(sbuff), NULL, 0, NI_NUMERICHOST);

        memset(&sd, 0, sizeof(sd));
        sd.sin_family = PF_INET;
        sd.sin_addr.s_addr = ip->daddr;
        getnameinfo((struct sockaddr *)&sd, sizeof(sd),
                    dbuff, sizeof(dbuff), NULL, 0, NI_NUMERICHOST);

        /* 打印出来地址信息 */
        printf("%s -> %s, ", sbuff, dbuff);
    }

    // printf("rxhash: 0x%x\n", ppd->hv1.tp_rxhash);
}

static void walk_block(struct block_desc *pbd, const int block_num)
{
    int num_pkts = pbd->h1.num_pkts, i;
    unsigned long bytes = 0;
    struct tpacket3_hdr *ppd;

    printf("walk_block -> num_pkts: %d\n", num_pkts);
    /* 获取当前块中第一个帧 */
    ppd = (struct tpacket3_hdr *)((uint8_t *)pbd +
                                  pbd->h1.offset_to_first_pkt);
    for (i = 0; i < num_pkts; ++i)
    {
        bytes += ppd->tp_snaplen;
        display(ppd);

        /* 获取下一个帧的位置 */
        ppd = (struct tpacket3_hdr *)((uint8_t *)ppd +
                                      ppd->tp_next_offset);
    }

    packets_total += num_pkts;
    bytes_total += bytes;
}

static void flush_block(struct block_desc *pbd)
{
    printf("flush_block\n");
    pbd->h1.block_status = TP_STATUS_KERNEL;
}

static void teardown_socket(struct ring *ring, int fd)
{
    /* 销毁套接字 */
    munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
    free(ring->rd);
    close(fd);
}

int main(int argc, char **argp)
{
    int fd, err;
    socklen_t len;
    struct ring ring;
    struct pollfd pfd;
    unsigned int block_num = 0, blocks = 64;
    struct block_desc *pbd;
    struct tpacket_stats_v3 stats;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s INTERFACE\n", argp[0]);
        return EXIT_FAILURE;
    }

    signal(SIGINT, sighandler);

    memset(&ring, 0, sizeof(ring));
    /* 初始化套接字 */
    fd = setup_socket(&ring, argp[argc - 1]);
    assert(fd > 0);

    /* 初始化poll参数 */
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR;
    pfd.revents = 0;

    /* 进入poll的循环收包环节 */
    while (likely(!sigint))
    {
        printf("-------\n");
        if (poll(&pfd, 1, -1) <= 0)
        {
            printf("poll error\n");
            continue;
        }
        printf("data commint\n");
        pbd = (struct block_desc *)ring.rd[block_num].iov_base;

        /* 检查当前块头的状态，判断是否有数据，没有的话就进行poll */
        if ((pbd->h1.block_status & TP_STATUS_USER) == 0)
        {
            printf("no data\n");
            // poll(&pfd, 1, -1);
            continue;
        }

        /* 有数据，遍历块里面的帧 */
        walk_block(pbd, block_num);
        /* 将块恢复为就绪状态 */
        flush_block(pbd);
        block_num = (block_num + 1) % blocks;
    }

    len = sizeof(stats);
    /* 获取报文统计信息，然后打印出来。 */
    err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
    if (err < 0)
    {
        perror("getsockopt");
        exit(1);
    }

    fflush(stdout);
    printf("\nReceived %u packets, %lu bytes, %u dropped, freeze_q_cnt: %u\n",
           stats.tp_packets, bytes_total, stats.tp_drops,
           stats.tp_freeze_q_cnt);

    teardown_socket(&ring, fd);
    return 0;
}

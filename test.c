// gcc packet_mmap_read_write.c -lpthread

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <poll.h>

#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

char const *const card_name = "enp6s0";

void *rx_ring_code(void *unused_param)
{
    int i;

    const int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }

    i = TPACKET_V3;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &i, sizeof(i)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }
    /*	i = ( ( getpid() & 0xffff ) | (PACKET_FANOUT_CPU << 16));
        if( setsockopt( sock, SOL_PACKET, PACKET_FANOUT, &i, sizeof(i) ) < 0 )
        {
            perror("setsockopt");
            return NULL;
        }
    */

    struct tpacket_req3 req =
        {
            .tp_block_size = 1 << 22,
            .tp_frame_size = 1 << 11,
            .tp_block_nr = 64,
        };
    struct ifreq ifr;
    strcpy(ifr.ifr_name, card_name);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)
    {
        perror("unable to get flags");
        return NULL;
    }
    ifr.ifr_flags |= (IFF_PROMISC | IFF_UP);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
    {
        perror("unable to set flags");
        return NULL;
    }
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &req, sizeof(struct tpacket_req3)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }

    uint8_t *const map = mmap(NULL, req.tp_block_size * req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sock, 0);
    if (map == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }

    struct sockaddr_ll ll =
        {
            .sll_family = PF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex = if_nametoindex(ifr.ifr_name)};

    if (bind(sock, (struct sockaddr *)&ll, sizeof(ll)) < 0)
    {
        perror("bind");
        exit(1);
    }

    struct pollfd pfd =
        {
            .fd = sock,
            .events = POLLIN | POLLERR,
            .revents = 0};

    int block_pos = 0;
    int pkt_num = 0;
    for (block_pos = 0; 1; block_pos = ((block_pos + 1) % req.tp_block_nr))
    {
        struct block_desc
        {
            uint32_t version;
            uint32_t offset_to_priv;
            struct tpacket_hdr_v1 h1;
        } *pbd = (struct block_desc *)(map + (block_pos * req.tp_block_size));

        if ((pbd->h1.block_status & TP_STATUS_USER) == 0)
        {
            poll(&pfd, 1, -1);
            continue;
        }
        printf("number of packets captured: %d\n", pbd->h1.num_pkts);
        struct tpacket3_hdr *ppd = (struct tpacket3_hdr *)((uint8_t *)pbd + pbd->h1.offset_to_first_pkt);
        for (i = 0; i < pbd->h1.num_pkts; i++)
        {
            printf("packet Number: %d packet size: %d\n", pkt_num++, ppd->tp_snaplen);
            /*uint8_t *pkt_ptr = ((uint8_t *) ppd + ppd->tp_mac);
            int j;
            for( j=0; j<ppd->tp_snaplen; j++ )
            {
                printf( "%02X ", pkt_ptr[j] );
            }
            printf( "\n" );
            ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd + ppd->tp_next_offset);*/
        }
        pbd->h1.block_status = TP_STATUS_KERNEL;
    }

    munmap(map, req.tp_block_size * req.tp_block_nr);
    close(sock);
    return 0;
}

void *tx_ring_code(void *unused_param)
{
    const int c_packet_sz = 200;
    int fd_socket, j;
    uint32_t i;

    fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_socket == -1)
    {
        perror("socket");
        return NULL;
    }
    struct sockaddr_ll my_addr =
        {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex = (int)if_nametoindex(card_name)};

    /* bind port */
    if (bind(fd_socket, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_ll)) == -1)
    {
        perror("bind");
        return NULL;
    }
    /* prepare Tx ring request */
    struct tpacket_req s_packet_req =
        {
            .tp_block_size = 1 << 12,
            .tp_frame_size = 1 << 12,
            .tp_block_nr = 10};
    s_packet_req.tp_frame_nr = (s_packet_req.tp_block_size * s_packet_req.tp_block_nr) / s_packet_req.tp_frame_size;

    /* send TX ring request */
    if (setsockopt(fd_socket, SOL_PACKET, PACKET_TX_RING, (char *)&s_packet_req, sizeof(s_packet_req)) < 0)
    {
        perror("setsockopt: PACKET_TX_RING");
        return NULL;
    }

    // int one = 1;
    // if (setsockopt(fd_socket, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one)) < 0)
    // {
    //     perror("setsockopt: PACKET_QDISC_BYPASS");
    //     return EXIT_FAILURE;
    // }

    /* mmap Tx ring buffers memory */
    struct tpacket_hdr *const map = mmap(0, s_packet_req.tp_block_size * s_packet_req.tp_block_nr, PROT_WRITE, MAP_SHARED, fd_socket, 0);
    if (map == MAP_FAILED)
    {
        perror("mmap");
        return NULL;
    }
    for (i = 0; i < s_packet_req.tp_block_nr; i++)
    {
        struct tpacket_hdr *ps_header = ((struct tpacket_hdr *)((void *)map + (s_packet_req.tp_block_size * i)));
#define my_TPACKET_ALIGN(x) (((x) + (uint64_t)(TPACKET_ALIGNMENT - 1)) & ~((uint64_t)(TPACKET_ALIGNMENT - 1)))
        char *pkt_ptr = ((void *)ps_header) + my_TPACKET_ALIGN(sizeof(struct tpacket_hdr));
        for (j = 0; j < c_packet_sz; j++)
        {
            pkt_ptr[j] = j; /* fill data in buffer */
        }
        /* update packet length */
        ps_header->tp_len = (uint32_t)c_packet_sz;
        ps_header->tp_status = TP_STATUS_SEND_REQUEST;
    }
    int total_pkts = 0, ec_send, total_bytes = 0;
    while (total_pkts < s_packet_req.tp_block_nr)
    {
        ec_send = sendto(fd_socket, NULL, 0, MSG_DONTWAIT, NULL, sizeof(struct sockaddr_ll));
        if (ec_send < 0)
        {
            perror("send");
        }
        else
        {
            total_pkts += ec_send / (c_packet_sz);
            total_bytes += ec_send;
            printf("%s %d send %d packets (+%d bytes)\n", __func__, __LINE__, total_pkts, total_bytes);
        }
    }
    munmap(map, s_packet_req.tp_block_size * s_packet_req.tp_block_nr);
    close(fd_socket);

    return NULL;
}

int main()
{
    pthread_t rx_thread, tx_thread;
    if (pthread_create(&rx_thread, NULL, rx_ring_code, NULL))
    {
        fprintf(stderr, "%s %d\n", __func__, __LINE__);
        return EXIT_FAILURE;
    }
    if (pthread_create(&tx_thread, NULL, tx_ring_code, NULL))
    {
        fprintf(stderr, "%s %d\n", __func__, __LINE__);
        return EXIT_FAILURE;
    }
    if (pthread_join(rx_thread, NULL))
    {
        fprintf(stderr, "%s %d\n", __func__, __LINE__);
        return EXIT_FAILURE;
    }
    if (pthread_join(tx_thread, NULL))
    {
        fprintf(stderr, "%s %d\n", __func__, __LINE__);
        return EXIT_FAILURE;
    }
}
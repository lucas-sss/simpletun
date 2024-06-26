/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun        *
 * interfaces and TCP. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.      *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2010 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <poll.h>
#include <sys/epoll.h>
#include <pthread.h>

/* buffer for reading from tun interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char *progname;
int epoll_fd;
int sock_fd;
int tun_fd;
// 暂存一个客户端的句柄
int client_fd;

int config_tun(char *dev, int mtu, char *ipv4, char *ipv4_net)
{
    char buf[512] = {0};

    printf("tun config -> dev: %s, mtu: %d, ipv4: %s, ipv4_net: %s\n", dev,
           mtu, ipv4, ipv4_net);

    // 设置mtu
    memset(buf, 0, sizeof(buf));
    system(buf);
    // 设置ipv4地址
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "ip addr add %s dev %s", ipv4, dev);
    system(buf);
    // 启动网卡
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "ip link set dev %s up", dev);
    system(buf);
    // 设置路由
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "route add -net %s dev %s", ipv4_net, dev);
    system(buf);

    return 0;
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun device. The caller         *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(int cliserv, char *dev, int flags)
{

    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0)
    {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

    // 配置虚拟网卡
    if (cliserv == SERVER)
    {
        config_tun(dev, 1500, "12.12.9.1", "12.12.9.0/24");
    }
    else
    {
        config_tun(dev, 1500, "12.12.9.2", "12.12.9.0/24");
    }

    return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n)
{

    int nread;

    if ((nread = read(fd, buf, n)) < 0)
    {
        perror("Reading data");
        exit(1);
    }
    return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n)
{

    int nwrite;

    if ((nwrite = write(fd, buf, n)) < 0)
    {
        perror("Writing data");
        exit(1);
    }
    return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n)
{

    int nread, left = n;

    while (left > 0)
    {
        if ((nread = cread(fd, buf, left)) == 0)
        {
            return 0;
        }
        else
        {
            left -= nread;
            buf += nread;
        }
    }
    return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...)
{

    va_list argp;

    if (debug)
    {
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...)
{

    va_list argp;

    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
}

void addEpollFd(int epollfd, int fd)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;
    int r = epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
    if (r)
    {
        printf("epoll_ctl add failed[%d], %s", errno, strerror(errno));
        exit(r);
    }
    do_debug("add fd[%d] events: %d\n", fd, ev.events);
}

int setNonBlock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        return errno;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void handleAccept()
{
    struct sockaddr_in raddr;
    socklen_t rsz = sizeof(raddr);
    int cfd;
    while ((cfd = accept4(sock_fd, (struct sockaddr *)&raddr, &rsz, SOCK_CLOEXEC)) >= 0)
    {
        struct sockaddr_in peer, local;
        socklen_t alen = sizeof(peer);
        int r = getpeername(cfd, (struct sockaddr *)&peer, &alen);
        if (r < 0)
        {
            printf("get peer name failed %d %s\n", errno, strerror(errno));
            continue;
        }
        r = getsockname(cfd, (struct sockaddr *)&local, &alen);
        if (r < 0)
        {
            printf("getsockname failed %d %s\n", errno, strerror(errno));
            continue;
        }
        setNonBlock(cfd);
        client_fd = cfd;

        // test

        addEpollFd(epoll_fd, cfd);
        do_debug("accept coonection from client[%d]\n", cfd);
        break;
    }
}

void handlerDataRead(int fd)
{
    uint16_t nread, nwrite, plength;
    char buffer[BUFSIZE];

    /* data from the network: read it, and write it to the tun interface.
     * We need to read the length first, and then the packet */

    /* Read length */
    nread = read_n(fd, (char *)&plength, sizeof(plength));
    if (nread == 0)
    {
        /* ctrl-c at the other end */
        do_debug("Read 0 bytes from network\n");
        return;
    }

    /* read packet */
    nread = read_n(fd, buffer, ntohs(plength));
    do_debug("Read %d bytes from network\n", nread);
    /* now buffer[] contains a full packet or frame, write it into the tun interface */
    nwrite = cwrite(tun_fd, buffer, nread);
    do_debug("Written %d bytes to tun interface\n", nwrite);
}

void handleRead(int fd)
{
    if (fd == sock_fd)
    {
        return handleAccept();
    }
    else
    {
        return handlerDataRead(fd);
    }
}

void handleWrite(int fd)
{
    // struct epoll_event ev;
    // memset(&ev, 0, sizeof(ev));
    // ev.events = events_;
    // ev.data.fd = fd;
    // int r = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

void *server_tun_thread(void *arg)
{
    uint16_t nread, nwrite, plength;
    char buffer[BUFSIZE];

    while (1)
    {
        /* data from tun: just read it and write it to the network */
        nread = cread(tun_fd, buffer, BUFSIZE);
        do_debug("Read %d bytes from the tun interface\n", nread);

        if (client_fd == 0)
        {
            do_debug("no client connect, ignore tun data\n");
            continue;
        }
        /* write length + packet */
        plength = htons(nread);
        nwrite = cwrite(client_fd, (char *)&plength, sizeof(plength));
        nwrite = cwrite(client_fd, buffer, nread);
        do_debug("Written %d bytes to the network\n", nwrite);
    }
}

void tunRead()
{
    // 创建server tun读取线程
    pthread_t serverTunThread;
    pthread_create(&serverTunThread, NULL, server_tun_thread, NULL);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-d]\n", progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
    fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
    fprintf(stderr, "-d: outputs debug information while running\n");
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}

int main(int argc, char *argv[])
{

    int net_fd, option, optval = 1;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    int maxfd;
    uint16_t nread, nwrite, plength;
    char buffer[BUFSIZE];
    struct sockaddr_in local, remote;
    char remote_ip[16] = ""; /* dotted quad IP string */
    unsigned short int port = PORT;
    socklen_t remotelen;
    int cliserv = -1; /* must be specified on cmd line */
    unsigned long int tap2net = 0, net2tap = 0;

    progname = argv[0];

    /* Check command line options */
    while ((option = getopt(argc, argv, "i:sc:p:hd")) > 0)
    {
        switch (option)
        {
        case 'd':
            debug = 1;
            break;
        case 'h':
            usage();
            break;
        case 'i':
            strncpy(if_name, optarg, IFNAMSIZ - 1);
            break;
        case 's':
            cliserv = SERVER;
            break;
        case 'c':
            cliserv = CLIENT;
            strncpy(remote_ip, optarg, 15);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        default:
            my_err("Unknown option %c\n", option);
            usage();
        }
    }

    argv += optind;
    argc -= optind;

    if (argc > 0)
    {
        my_err("Too many options!\n");
        usage();
    }

    if (*if_name == '\0')
    {
        my_err("Must specify interface name!\n");
        usage();
    }
    else if (cliserv < 0)
    {
        my_err("Must specify client or server mode!\n");
        usage();
    }
    else if ((cliserv == CLIENT) && (*remote_ip == '\0'))
    {
        my_err("Must specify server address!\n");
        usage();
    }

    /* initialize tun interface */
    if ((tun_fd = tun_alloc(cliserv, if_name, flags | IFF_NO_PI)) < 0)
    {
        my_err("Error connecting to tun interface %s!\n", if_name);
        exit(1);
    }

    do_debug("Successfully connected to interface %s\n", if_name);

    if ((sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)) < 0)
    {
        perror("socket()");
        exit(1);
    }

    if (cliserv == CLIENT)
    {
        /* Client, try to connect to server */

        /* assign the destination address */
        memset(&remote, 0, sizeof(remote));
        remote.sin_family = AF_INET;
        remote.sin_addr.s_addr = inet_addr(remote_ip);
        remote.sin_port = htons(port);

        /* connection request */
        if (connect(sock_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0)
        {
            perror("connect()");
            exit(1);
        }

        net_fd = sock_fd;
        do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    }
    else
    {
        /* Server, wait for connections */

        /* avoid EADDRINUSE error on bind() */
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
        {
            perror("setsockopt()");
            exit(1);
        }
        setNonBlock(sock_fd);

        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(port);
        if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0)
        {
            perror("bind()");
            exit(1);
        }

        if (listen(sock_fd, 5) < 0)
        {
            perror("listen()");
            exit(1);
        }

        /* wait for connection request */
        // create epoll
        epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        addEpollFd(epoll_fd, sock_fd);

        client_fd = 0;
        tunRead();

        // remotelen = sizeof(remote);
        // memset(&remote, 0, remotelen);
        // if ((net_fd = accept(sock_fd, (struct sockaddr *)&remote, &remotelen)) < 0)
        // {
        //     perror("accept()");
        //     exit(1);
        // }

        // do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
    }

    /* use epoll() to handle client connect or data */
    while (1)
    {
        const int kMaxEvents = 10240;
        struct epoll_event activeEvs[kMaxEvents];

        int n = epoll_wait(epoll_fd, activeEvs, kMaxEvents, 100);
        int i;
        for (i = n - 1; i >= 0; i--)
        {
            int fd = activeEvs[i].data.fd;
            int events = activeEvs[i].events;
            if (events & (EPOLLIN | EPOLLERR))
            {
                do_debug("fd[%d] handle read\n", fd);
                handleRead(fd);
            }
            // else if (events & EPOLLOUT)
            // {
            //     printf("fd[%d] handle write\n", fd);
            //     handleWrite(fd);
            // }
            else
            {
                printf("unknown event %d\n", events);
            }
        }
    }

    // /* use select() to handle two descriptors at once */
    // maxfd = (tun_fd > net_fd) ? tun_fd : net_fd;
    // while (1)
    // {
    //     int ret;
    //     fd_set rd_set;

    //     FD_ZERO(&rd_set);
    //     FD_SET(tun_fd, &rd_set);
    //     FD_SET(net_fd, &rd_set);

    //     ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    //     if (ret < 0 && errno == EINTR)
    //     {
    //         continue;
    //     }

    //     if (ret < 0)
    //     {
    //         perror("select()");
    //         exit(1);
    //     }

    //     if (FD_ISSET(tun_fd, &rd_set))
    //     {
    //         /* data from tun: just read it and write it to the network */
    //         nread = cread(tun_fd, buffer, BUFSIZE);
    //         tap2net++;
    //         do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

    //         /* write length + packet */
    //         plength = htons(nread);
    //         nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
    //         nwrite = cwrite(net_fd, buffer, nread);

    //         do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    //     }

    //     if (FD_ISSET(net_fd, &rd_set))
    //     {
    //         /* data from the network: read it, and write it to the tun interface.
    //          * We need to read the length first, and then the packet */

    //         /* Read length */
    //         nread = read_n(net_fd, (char *)&plength, sizeof(plength));
    //         if (nread == 0)
    //         {
    //             /* ctrl-c at the other end */
    //             break;
    //         }
    //         net2tap++;

    //         /* read packet */
    //         nread = read_n(net_fd, buffer, ntohs(plength));
    //         do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

    //         /* now buffer[] contains a full packet or frame, write it into the tun interface */
    //         nwrite = cwrite(tun_fd, buffer, nread);
    //         do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    //     }
    // }

    return (0);
}

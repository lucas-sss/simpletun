// #include <iostream>     //控制台输出
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>       //虚拟网卡
#include <linux/if_tun.h> //虚拟网卡
#include <sys/ioctl.h>    //fd设置
#include <stdarg.h>       //参数解析
#include <pthread.h>      //创建线程
#include <errno.h>        //处理错误码
#include <signal.h>       //处理信号

#include <sys/socket.h> //创建socket
#include <netinet/in.h> //socket addr
#include <sys/epoll.h>  //epoll
#include <unistd.h>     //close函数
#include <fcntl.h>      //设置非阻塞

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define log(...)             \
    do                       \
    {                        \
        printf(__VA_ARGS__); \
        fflush(stdout);      \
    } while (0)
#define check1(x, ...)        \
    if (x)                    \
        do                    \
        {                     \
            log(__VA_ARGS__); \
            exit(1);          \
    } while (0)
#define check0(x, ...)        \
    if (!x)                   \
        do                    \
        {                     \
            log(__VA_ARGS__); \
            exit(1);          \
    } while (0)

#define BUFSIZE 2000
#define EVENTS_SIZE 20

#define VPN_LABEL_LEN 2
#define RECORD_TYPE_LABEL_LEN 2
#define RECORD_LENGTH_LABEL_LEN 4

#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')

typedef struct
{
    int fd;
    uint8_t net;
    uint8_t tun;
} event_data_t;

const unsigned char VPN_LABEL[VPN_LABEL_LEN] = {0x10, 0x10};                                // vpn标记
const unsigned char RECORD_TYPE_DATA[RECORD_TYPE_LABEL_LEN] = {0x11, 0x10};                 // vpn数据标记
const unsigned char RECORD_TYPE_CONTROL[RECORD_TYPE_LABEL_LEN] = {0x12, 0x10};              // vpn控制协议标记
const unsigned char RECORD_TYPE_CONTROL_TUN_CONFIG[RECORD_TYPE_LABEL_LEN] = {0x12, 0x11};   // vpn虚拟网卡配置控制协议
const unsigned char RECORD_TYPE_CONTROL_ROUTE_CONFIG[RECORD_TYPE_LABEL_LEN] = {0x12, 0x12}; // vpn路由配置控制协议
const unsigned char RECORD_TYPE_AUTH[RECORD_TYPE_LABEL_LEN] = {0x13, 0x10};                 // vpn认证协议
const unsigned char RECORD_TYPE_AUTH_ACCOUNT[RECORD_TYPE_LABEL_LEN] = {0x13, 0x11};         // vpn账号认证协议
const unsigned char RECORD_TYPE_AUTH_PHONE[RECORD_TYPE_LABEL_LEN] = {0x13, 0x12};           // vpn短信认证协议
const unsigned char RECORD_TYPE_AUTH_TOKEN[RECORD_TYPE_LABEL_LEN] = {0x13, 0x13};           // vpn动态口令认证协议
const unsigned char RECORD_TYPE_ALARM[RECORD_TYPE_LABEL_LEN] = {0x14, 0x10};                // vpn告警协议

const unsigned int HEADER_LEN = VPN_LABEL_LEN + RECORD_TYPE_LABEL_LEN + RECORD_LENGTH_LABEL_LEN;
const unsigned int RECORD_HEADER_LEN = RECORD_TYPE_LABEL_LEN + RECORD_LENGTH_LABEL_LEN;

int debug = 0;
int clientfd = -1;
int tunfd = -1;
int epollfd = -1;
int g_stop = 0;

BIO *errBio;
SSL_CTX *g_sslCtx;

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

/**
 * dump_hex
 *
 * @brief dump data in hex format
 *
 * @param buf: User buffer
 * @param size: Dump data size
 * @param number: The number of outputs per line
 *
 * @return void
 */
void dump_hex(const uint8_t *buf, uint32_t size, uint32_t number)
{
    int i, j;

    for (i = 0; i < size; i += number)
    {
        printf("%08X: ", i);

        for (j = 0; j < number; j++)
        {
            if (j % 8 == 0)
            {
                printf(" ");
            }
            if (i + j < size)
                printf("%02X ", buf[i + j]);
            else
                printf("   ");
        }
        printf(" ");

        for (j = 0; j < number; j++)
        {
            if (i + j < size)
            {
                printf("%c", __is_print(buf[i + j]) ? buf[i + j] : '.');
            }
        }
        printf("\n");
    }
}

/**
 * @brief 对数据包进行编码 VPN_LABEL[2] + RECORD_LABEL[2] + DATA_LENGTH[4] + data
 *
 * @param type
 * @param in
 * @param in_len
 * @param out
 * @param out_len
 * @return int
 */
int enpack(const unsigned char type[RECORD_TYPE_LABEL_LEN], unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len)
{
    if (in == NULL || out == NULL || out_len == NULL)
    {
        return -1;
    }

    if (in_len + HEADER_LEN > *out_len)
    {
        return -1;
    }

    int len = 0;

    memcpy(out, VPN_LABEL, VPN_LABEL_LEN);
    len += VPN_LABEL_LEN;
    memcpy(out + len, type, RECORD_TYPE_LABEL_LEN);
    len += RECORD_TYPE_LABEL_LEN;
    memcpy(out + len, &in_len, RECORD_LENGTH_LABEL_LEN);
    len += RECORD_LENGTH_LABEL_LEN;
    memcpy(out + len, in, in_len);
    len += in_len;
    *out_len = len;

    return 0;
}

/**
 * @brief 对数据进行解包
 *
 * @param in        输入数据
 * @param in_len    输入数据长度
 * @param out       输出数据
 * @param out_len   输出数据长度
 * @param next      剩余数据
 * @param next_len  剩余数据长度
 * @return int 1解析出数据包，0未解析出数据包，-1非协议数据
 */
int depack(unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len, unsigned char **next, unsigned int *next_len)
{
    // printf("输入数据长度: %d\n", in_len);
    if (in == NULL || out == NULL || next == NULL || next_len == NULL)
    {
        // printf("in == NULL || out == NULL || next == NULL || *next_len == NULL\n");
        return 0;
    }

    if (in_len < HEADER_LEN)
    { // 数据不足消息头长度
        // printf("数据不足消息头长度, in_len: %d\n", in_len);
        *next = in;
        *next_len = in_len;
        return 0;
    }

    if (memcmp(in, VPN_LABEL, VPN_LABEL_LEN) == 0)
    { // 是vpn协议才进行解析
        unsigned int *length = (unsigned int *)(in + VPN_LABEL_LEN + RECORD_TYPE_LABEL_LEN);
        // printf("解析数据包长度: %d\n", *length);
        if (in_len < (HEADER_LEN + *length))
        { // 剩余可解析数据长度小于标记长度，需要继续读取
            // printf("剩余可解析数据长度小于标记长度，需要继续读取\n");
            *next = in;
            *next_len = in_len;
            return 0;
        }

        if (*out_len < (RECORD_HEADER_LEN + *length))
        { // 输出缓存数据长度不够
            // printf("输出缓存数据长度不够\n");
            *next = in;
            *next_len = in_len;
            return 0;
        }

        memcpy(out, in + VPN_LABEL_LEN, RECORD_HEADER_LEN + *length);
        *out_len = (RECORD_HEADER_LEN + *length);

        if (in_len == (HEADER_LEN + *length))
        {
            // 数据是完整的，没有剩余待解析的数据
            // printf("数据是完整的，没有剩余待解析的数据\n");
            *next = NULL;
            *next_len = 0;
            return 1;
        }
        *next = (in + HEADER_LEN + *length);
        *next_len = (in_len - HEADER_LEN - *length);
        // printf("有未解析数据, 剩余数据长度: %d\n", *next_len);
        // dump_hex(*next, *next_len, 32);
        if (*next_len > 8)
        {
            unsigned int *plength = (unsigned int *)(*next + VPN_LABEL_LEN + RECORD_TYPE_LABEL_LEN);
            // printf("下一个数据包长度: %d\n", *plength);
        }
        return 1;
    }
    // 不是vpn协议
    // printf("不是vpn协议\n");
    return -1;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    SSL *ssl;
    X509 *cert;
    char *line;
    printf("verify_callback -> preverify_ok: %d\n", preverify_ok);

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert != NULL)
    {
        printf("客户端证书:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("使用者: %s\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    }

    return preverify_ok;
}

void initSSL()
{
    int r;
    int verifyClient = 0;
    int useTLS13 = 0;
    char *ca = "certs/ca.crt";
    char *signcert = "certs/signcert.crt";
    char *singkey = "certs/signkey.key";
    char *enccert = "certs/enccert.crt";
    char *enckey = "certs/enckey.key";
    char *cert = "certs/server.pem";
    char *key = "certs/server.pem";
    char *crl = "";

    SSL_load_error_strings();
    r = SSL_library_init();
    check1(!r, "SSL_library_init failed");
    errBio = BIO_new_fd(2, BIO_NOCLOSE);

    // 使用SSLv23_method可以同时支持客户同时支持rsa证书和sm2证书，支持普通浏览器和国密浏览器的访问
    // g_sslCtx = SSL_CTX_new(SSLv23_method());
    // 双证书相关server的各种定义
    const SSL_METHOD *meth = NTLS_server_method();
    g_sslCtx = SSL_CTX_new(meth);
    check1(g_sslCtx == NULL, "SSL_CTX_new failed");

    // 允许使用国密双证书功能
    SSL_CTX_enable_ntls(g_sslCtx);

    if (useTLS13)
    {
        printf("enable tls13 sm2 sign");
        // tongsuo中tls1.3不强制签名使用sm2签名，使用开关控制，对应客户端指定密码套件SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
        SSL_CTX_enable_sm_tls13_strict(g_sslCtx);
        SSL_CTX_set1_curves_list(g_sslCtx, "SM2:X25519:prime256v1");
    }

    // 设置密码套件
    SSL_CTX_set_cipher_list(g_sslCtx, "ECC-SM2-SM4-CBC-SM3:ECDHE-SM2-WITH-SM4-SM3:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!RC4:!EXPORT:!DES:!3DES:!MD5:!DSS:!PKS");
    SSL_CTX_set_options(g_sslCtx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    // 是否校验客户端
    if (verifyClient)
    {
        printf("need verify client\n");
        SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_PEER, verify_callback); // 验证客户端证书回调；
        // SSL_CTX_set_verify_depth(g_sslCtx, 0);
        r = SSL_CTX_load_verify_locations(g_sslCtx, ca, NULL);
        check1(r <= 0, "SSL_CTX_load_verify_locations %s failed", ca);
        ERR_clear_error();
        STACK_OF(X509_NAME) *list = SSL_load_client_CA_file(ca);
        check1(list == NULL, "SSL_load_client_CA_file %s failed", ca);
        SSL_CTX_set_client_CA_list(g_sslCtx, list);
    }
    else
    {
        printf("not need verify client\n");
        SSL_CTX_set_verify(g_sslCtx, SSL_VERIFY_NONE, NULL); // 不验证客户端；
    }

    if (strlen(crl) > 0)
    {
        X509_STORE *store = NULL;
        X509_LOOKUP *lookup = NULL;

        store = SSL_CTX_get_cert_store(g_sslCtx);
        check1(store == NULL, "SSL_CTX_get_cert_store() failed");

        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        check1(store == NULL, "X509_STORE_add_lookup() failed");

        r = X509_LOOKUP_load_file(lookup, crl, X509_FILETYPE_PEM);
        check1(store == NULL, "X509_LOOKUP_load_file(\"%s\") failed", crl);

        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        printf("local crl finish\n");
    }

    // 加载sm2证书
    r = SSL_CTX_use_sign_PrivateKey_file(g_sslCtx, singkey, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_sign_PrivateKey_file %s failed", singkey);
    r = SSL_CTX_use_sign_certificate_file(g_sslCtx, signcert, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_sign_certificate_file %s failed", signcert);
    r = SSL_CTX_use_enc_PrivateKey_file(g_sslCtx, enckey, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_enc_PrivateKey_file %s failed", enckey);
    r = SSL_CTX_use_enc_certificate_file(g_sslCtx, enccert, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_enc_certificate_file %s failed", enccert);
    printf("load sm2 cert key finish\n");

    // 加载rsa证书
    r = SSL_CTX_use_certificate_file(g_sslCtx, cert, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_certificate_file %s failed", cert);
    r = SSL_CTX_use_PrivateKey_file(g_sslCtx, key, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_PrivateKey_file %s failed", key);
    printf("load rsa cert key finish\n");

    r = SSL_CTX_check_private_key(g_sslCtx);
    check1(!r, "SSL_CTX_check_private_key failed");
    printf("SSL inited\n");
}

void *server_tun_thread(void *arg)
{
    size_t rlen = 0;
    unsigned char buf[BUFSIZE];
    unsigned char packet[BUFSIZE + HEADER_LEN];
    unsigned int enpack_len = 0, nwrite = 0;

    // 2、读取虚拟网卡数据
    while (1)
    {
        // 1、读取tun网卡数据
        rlen = read(tunfd, buf, sizeof(buf));
        if (rlen < 0)
        {
            printf("tun read len < 0\n");
            break;
        }
        // 2、分析报文
        unsigned char src_ip[4];
        unsigned char dst_ip[4];
        memcpy(dst_ip, &buf[16], 4);
        memcpy(src_ip, &buf[12], 4);
        // do_debug("read tun data: %d.%d.%d.%d -> %d.%d.%d.%d (%d)\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], src_ip[0], src_ip[1], src_ip[2], src_ip[3], rlen);

        // 3、对数据进行封包处理
        enpack_len = sizeof(packet);
        enpack(RECORD_TYPE_DATA, buf, rlen, packet, &enpack_len);

        // 4、TODO 查找客户端

        // 5、发消息给客户端
        if (clientfd != -1)
        {
            nwrite = write(clientfd, packet, enpack_len);
            // do_debug("Written %d bytes to the network\n", nwrite);
        }
        else
        {
            printf("not fond client\n");
        }
    }
    return NULL;
}

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
int tun_alloc(char *dev, int flags)
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
    // strcpy(dev, ifr.ifr_name);
    // 配置虚拟网卡
    config_tun(dev, 1500, "12.12.9.1", "12.12.9.0/24");

    return fd;
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "-d: outputs debug information while running\n");
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}

void handleInterrupt(int sig)
{
    g_stop = 1;
}

int main(int argc, char *argv[])
{
    int option, ret;
    // 读socket的数组
    unsigned char *next = NULL;
    unsigned int nextlen = 0;
    unsigned char buff[BUFSIZE];
    unsigned char tmp_buff[BUFSIZE];
    unsigned char tun_data[BUFSIZE];
    unsigned char enpack_buff[BUFSIZE + HEADER_LEN];
    unsigned int enpack_len = sizeof(enpack_buff);
    unsigned char depack_buff[BUFSIZE];
    unsigned int depack_len = sizeof(depack_buff);
    unsigned int plength;
    int nwrite, nread;
    char dev[128] = {0};

    // signal(SIGINT, handleInterrupt);

    /* Check command line options */
    while ((option = getopt(argc, argv, "hd")) > 0)
    {
        switch (option)
        {
        case 'd':
            debug = 1;
            break;
        case 'h':
            usage();
            break;
        default:
            printf("Unknown option %c\n", option);
            usage();
        }
    }

    // 创建虚拟网卡
    memcpy(dev, "tun11", sizeof("tun11"));
    tunfd = tun_alloc(dev, IFF_TUN | IFF_NO_PI);
    if (tunfd <= 0)
    {
        perror("tun_alloc error");
        return -1;
    }
    printf("create tun fd: %d\n", tunfd);

    // 创建server tun读取线程
    pthread_t serverTunThread;
    ret = pthread_create(&serverTunThread, NULL, server_tun_thread, &tunfd);
    if (ret != 0)
    {
        printf("create server tun thread fail: %d", ret);
        return -1;
    }

    // 创建一个tcp socket
    int socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int enable = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    int flags = fcntl(socketFd, F_GETFL, 0);
    if (flags < 0)
    {
        perror("fcntl F_GETFL error");
        return -1;
    }
    fcntl(socketFd, F_SETFL, flags | O_NONBLOCK);

    // 设置socket监听的地址和端口
    struct sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sin_port = htons(55555);
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = htons(INADDR_ANY);

    // 将socket和地址绑定
    if (bind(socketFd, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) == -1)
    {
        perror("bind error");
        return -1;
    }

    // 开始监听socket,当调用listen之后,
    // 进程就可以调用accept来接受一个外来的请求
    // 第二个参数,请求队列的长度
    if (listen(socketFd, 10) == -1)
    {
        perror("listen error");
        return -1;
    }

    // 创建一个epoll,size已经不起作用了,一般填1就好了
    int eFd = epoll_create(1);
    epollfd = eFd;

    // 把socket包装成一个epoll_event对象
    // 并添加到epoll中
    struct epoll_event epev;
    memset(&epev, 0, sizeof(epev));
    epev.events = EPOLLIN | EPOLLET;                // 可以响应的事件,这里只响应可读就可以了
    epev.data.fd = socketFd;                        // socket的文件描述符
    epoll_ctl(eFd, EPOLL_CTL_ADD, socketFd, &epev); // 添加到epoll中

    // 初始化next
    next = NULL;
    nextlen = 0;

    // 回调事件的数组,当epoll中有响应事件时,通过这个数组返回
    struct epoll_event events[EVENTS_SIZE];

    // 整个epoll_wait 处理都要在一个死循环中处理
    while (!g_stop)
    {
        // 这个函数会阻塞,直到超时或者有响应事件发生
        int eNum = epoll_wait(eFd, events, EVENTS_SIZE, -1);

        if (eNum == -1)
        {
            perror("epoll_wait");
            return -1;
        }
        // 遍历所有的事件
        for (int i = 0; i < eNum; i++)
        {
            // 判断这次是不是socket可读(是不是有新的连接)
            int fd = events[i].data.fd;
            if (fd == socketFd)
            {
                if (events[i].events & EPOLLIN)
                {
                    struct sockaddr_in cli_addr;
                    socklen_t length = sizeof(cli_addr);
                    // 接受来自socket连接
                    int newfd = accept(socketFd, (struct sockaddr *)&cli_addr, &length);
                    if (newfd > 0)
                    {
                        // 设置连接为非阻塞模式
                        int flags = fcntl(newfd, F_GETFL, 0);
                        if (flags < 0)
                        {
                            printf("get fd[%d] fcntl error\n", newfd);
                            continue;
                        }
                        if (fcntl(newfd, F_SETFL, flags | O_NONBLOCK) < 0)
                        {
                            printf("set no block error, fd: %d\n", newfd);
                            continue;
                        }

                        event_data_t *eventdata = (event_data_t *)malloc(sizeof(event_data_t));
                        if (eventdata == NULL)
                        {
                            perror("malloc event_data_t");
                        }
                        memset(eventdata, 0, sizeof(event_data_t));
                        eventdata->fd = newfd;
                        eventdata->net = 1;

                        // 设置响应事件,设置可读和边缘(ET)模式
                        // 很多人会把可写事件(EPOLLOUT)也注册了,后面会解释
                        memset(&epev, 0, sizeof(epev));
                        epev.events = EPOLLIN;
                        epev.data.fd = newfd;
                        epev.data.ptr = eventdata;
                        epoll_ctl(eFd, EPOLL_CTL_ADD, newfd, &epev);
                        printf("client on line fd: %d\n", newfd);

                        clientfd = newfd;
                    }
                }
            }
            else
            { // 不是socket的响应事件

                // 判断是不是断开和连接出错
                // 因为连接断开和出错时,也会响应`EPOLLIN`事件
                if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
                {
                    // 出错时,从epoll中删除对应的连接
                    // 第一个是要操作的epoll的描述符
                    // 因为是删除,所有event参数天null就可以了
                    printf("connect exception, client out fd: %d\n", events[i].data.fd);
                    epoll_ctl(eFd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    close(events[i].data.fd);

                    event_data_t *eventdata = (event_data_t *)events[i].data.ptr;
                    if (eventdata != NULL)
                    {
                        free(eventdata);
                    }
                }
                else if (events[i].events & EPOLLIN)
                { // 如果是可读事件
                    event_data_t *eventdata = (event_data_t *)events[i].data.ptr;
                    if (eventdata == NULL)
                    {
                        printf("eventdata is NULL\n");
                        epoll_ctl(eFd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                        close(events[i].data.fd);
                        continue;
                    }
                    do_debug("fd[%d] data comming\n", eventdata->fd);

                    if (eventdata->net == 1)
                    {
                        if (next == NULL)
                        {
                            do_debug("not have next data\n");
                            next = buff;
                            nextlen = 0;
                        }
                        else
                        {
                            do_debug("have next data, next: %p, nextlen: %d\n", next, nextlen);
                            // dump_hex(next, nextlen, 32);
                        }

                        int l = BUFSIZE - nextlen;
                        do_debug("client data -> next: %p, nextlen: %d, next偏移量: %d, 可用空间size: %d\n", next, nextlen, next - buff, l);

                        int len = read(eventdata->fd, next + nextlen, BUFSIZE - nextlen);
                        do_debug("read client data len: %d\n", len);

                        // 如果读取数据出错,关闭并从epoll中删除连接
                        if (len <= 0)
                        {
                            printf("read error[%d]\n", errno);
                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                            {
                                printf("无数据可度\n");
                                continue;
                            }

                            printf("read error, client out fd: %d\n", eventdata->fd);
                            epoll_ctl(eFd, EPOLL_CTL_DEL, eventdata->fd, NULL);
                            close(eventdata->fd);
                            continue;
                        }

                        // 对数据进行解包
                        int ret = 0, count = 1;
                        depack_len = sizeof(depack_buff);

                        int plen = len + nextlen;
                        while ((ret = depack(next, plen, depack_buff, &depack_len, &next, &nextlen)) > 0)
                        {
                            int datalen = depack_len - RECORD_HEADER_LEN;
                            // 判定数据类型
                            if (memcmp(depack_buff, RECORD_TYPE_DATA, RECORD_TYPE_LABEL_LEN) == 0) // vpn数据
                            {
                                /* 3、写入到虚拟网卡 */
                                int wlen = write(tunfd, depack_buff + RECORD_HEADER_LEN, datalen);
                                if (wlen < datalen)
                                {
                                    printf("虚拟网卡写入数据长度小于预期长度, write len: %d, buffer len: %d\n", wlen, len);
                                }
                            }
                            else
                            {
                                printf("未定义协议类型:\n");
                                // dump_hex(depack_buff, 2, 32);
                            }
                            depack_len = sizeof(depack_buff);
                            count++;
                            if (next == NULL)
                            {
                                break;
                            }
                            // printf("第%d次解析数据完成, 还需进行下一次解析, 遗留数据长度: %d\n", count, nextlen);
                            plen = nextlen;
                        }
                        if (ret == 0 && next != NULL)
                        {
                            memcpy(tmp_buff, next, nextlen);
                            memcpy(buff, tmp_buff, nextlen);
                            next = buff;
                        }
                        if (ret < 0)
                        {
                            printf("next: %p, 非vpn协议数据:\n", next);
                            // dump_hex(next, len, 32);
                            exit(-1);
                        }
                    }

                    if (eventdata->tun == 1)
                    { // 网卡可读事件
                        do_debug("tun data\n");

                        nread = read(tunfd, tun_data, BUFSIZE);
                        if (nread < 0)
                        {
                            printf("tun read error\n");
                            continue;
                        }
                        // do_debug("Read %d bytes from the tun interface\n", nread);

                        enpack_len = sizeof(enpack_buff);
                        enpack(RECORD_TYPE_DATA, tun_data, (unsigned int)nread, enpack_buff, &enpack_len);

                        if (clientfd != -1)
                        {
                            nwrite = write(clientfd, enpack_buff, enpack_len);
                            // do_debug("Written %d bytes to the network\n", nwrite);
                        }
                        else
                        {
                            printf("not fond client\n");
                        }
                    }
                }
            }
        }
    }
    printf("程序退出！\n");
    close(socketFd);
    close(epollfd);
}
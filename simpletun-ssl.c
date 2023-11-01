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

/* buffer for reading from tun interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char *progname;

#define VPN_LABEL_LEN 2
#define RECORD_TYPE_LABEL_LEN 2
#define RECORD_LENGTH_LABEL_LEN 4

typedef struct
{
    int fd;
    uint8_t net;
    uint8_t tun;
} event_data_t;

int useTLS13 = 0;
int useDHE = 0;
int verifyClient = 0;
BIO *errBio;

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

int depack(unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len, unsigned char **next, unsigned int *next_len)
{
    if (in == NULL || out == NULL || next == NULL || next_len == NULL)
    {
        return 0;
    }

    if (in_len < HEADER_LEN)
    { // 数据不足消息头长度
        *next = in;
        *next_len = in_len;
        return 0;
    }

    if (memcmp(in, VPN_LABEL, VPN_LABEL_LEN) == 0)
    { // 是vpn协议才进行解析
        unsigned int *length = (unsigned int *)(in + VPN_LABEL_LEN + RECORD_TYPE_LABEL_LEN);
        if (in_len < (HEADER_LEN + *length))
        { // 剩余可解析数据长度小于标记长度，需要继续读取
            *next = in;
            *next_len = in_len;
            return 0;
        }

        if (*out_len < (RECORD_HEADER_LEN + *length))
        { // 输出缓存数据长度不够
            *next = in;
            *next_len = in_len;
            return 0;
        }

        memcpy(out, in + VPN_LABEL_LEN, RECORD_HEADER_LEN + *length);
        *out_len = (RECORD_HEADER_LEN + *length);

        if (in_len == (HEADER_LEN + *length))
        {
            // 数据是完整的，没有剩余待解析的数据
            *next = NULL;
            *next_len = 0;
            return 1;
        }
        *next = (in + HEADER_LEN + *length);
        *next_len = (in_len - HEADER_LEN - *length);
        return 1;
    }
    // 不是vpn协议
    // *next = NULL;
    *next_len = 0;
    return -1;
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

SSL_CTX *createClientSslCtx()
{
    int ret = 0;
    // 变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    const char *sign_key_file = "certs/signclient.key";
    const char *sign_cert_file = "certs/signclient.crt";
    const char *enc_key_file = "certs/encclient.key";
    const char *enc_cert_file = "certs/encclient.crt";

    // 双证书相关client的各种定义
    meth = NTLS_client_method();
    // 生成上下文
    ctx = SSL_CTX_new(meth);
    // 允许使用国密双证书功能
    SSL_CTX_enable_ntls(ctx);

    if (useTLS13)
    {
        // 对于tls1.3: 设置算法套件为TLS_SM4_GCM_SM3/TLS_SM4_CCM_SM3
        SSL_CTX_set1_curves_list(ctx, "SM2:X25519:prime256v1");
        ret = SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
    }
    else
    {
        // 对于tlcp: 设置算法套件为ECC-SM2-WITH-SM4-SM3或者ECDHE-SM2-WITH-SM4-SM3,
        // 这一步并不强制编写，默认ECC-SM2-WITH-SM4-SM3优先
        if (useDHE)
        {
            printf("use ECDHE-SM2-WITH-SM4-SM3\n");
            ret = SSL_CTX_set_cipher_list(ctx, "ECDHE-SM2-WITH-SM4-SM3");
            // 加载签名证书，加密证书，仅ECDHE-SM2-WITH-SM4-SM3套件需要这一步,
            // 该部分流程用...begin...和...end...注明
            //  ...begin...
            if (!SSL_CTX_use_sign_PrivateKey_file(ctx, sign_key_file, SSL_FILETYPE_PEM))
            {
                goto err;
            }
            if (!SSL_CTX_use_sign_certificate_file(ctx, sign_cert_file, SSL_FILETYPE_PEM))
            {
                goto err;
            }
            if (!SSL_CTX_use_enc_PrivateKey_file(ctx, enc_key_file, SSL_FILETYPE_PEM))
            {
                goto err;
            }
            if (!SSL_CTX_use_enc_certificate_file(ctx, enc_cert_file, SSL_FILETYPE_PEM))
            {
                goto err;
            }
            // ...end...
        }
        else
        {
            printf("use ECC-SM2-WITH-SM4-SM3\n");
            ret = SSL_CTX_set_cipher_list(ctx, "ECC-SM2-WITH-SM4-SM3");
        }
    }

    if (ret <= 0)
    {
        printf("SSL_CTX_set_cipher_list fail\n");
        goto err;
    }
    return ctx;
err:
    SSL_CTX_free(ctx);
    return NULL;
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

SSL_CTX *createServerSslCtx()
{
    int r;
    SSL_CTX *ctx = NULL;
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
    ctx = SSL_CTX_new(meth);
    check1(ctx == NULL, "SSL_CTX_new failed");

    // 允许使用国密双证书功能
    SSL_CTX_enable_ntls(ctx);

    if (useTLS13)
    {
        printf("enable tls13 sm2 sign");
        // tongsuo中tls1.3不强制签名使用sm2签名，使用开关控制，对应客户端指定密码套件SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
        SSL_CTX_enable_sm_tls13_strict(ctx);
        SSL_CTX_set1_curves_list(ctx, "SM2:X25519:prime256v1");
    }

    // 设置密码套件
    SSL_CTX_set_cipher_list(ctx, "ECC-SM2-SM4-CBC-SM3:ECDHE-SM2-WITH-SM4-SM3:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:ECDHE-RSA-AES128-SHA256:!aNULL:!eNULL:!RC4:!EXPORT:!DES:!3DES:!MD5:!DSS:!PKS");
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    // 是否校验客户端
    if (verifyClient)
    {
        printf("need verify client\n");
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback); // 验证客户端证书回调；
        // SSL_CTX_set_verify_depth(g_sslCtx, 0);
        r = SSL_CTX_load_verify_locations(ctx, ca, NULL);
        check1(r <= 0, "SSL_CTX_load_verify_locations %s failed", ca);
        ERR_clear_error();
        STACK_OF(X509_NAME) *list = SSL_load_client_CA_file(ca);
        check1(list == NULL, "SSL_load_client_CA_file %s failed", ca);
        SSL_CTX_set_client_CA_list(ctx, list);
    }
    else
    {
        printf("not need verify client\n");
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // 不验证客户端；
    }

    if (strlen(crl) > 0)
    {
        X509_STORE *store = NULL;
        X509_LOOKUP *lookup = NULL;

        store = SSL_CTX_get_cert_store(ctx);
        check1(store == NULL, "SSL_CTX_get_cert_store() failed");

        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        check1(store == NULL, "X509_STORE_add_lookup() failed");

        r = X509_LOOKUP_load_file(lookup, crl, X509_FILETYPE_PEM);
        check1(store == NULL, "X509_LOOKUP_load_file(\"%s\") failed", crl);

        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        printf("local crl finish\n");
    }

    // 加载sm2证书
    r = SSL_CTX_use_sign_PrivateKey_file(ctx, singkey, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_sign_PrivateKey_file %s failed", singkey);
    r = SSL_CTX_use_sign_certificate_file(ctx, signcert, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_sign_certificate_file %s failed", signcert);
    r = SSL_CTX_use_enc_PrivateKey_file(ctx, enckey, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_enc_PrivateKey_file %s failed", enckey);
    r = SSL_CTX_use_enc_certificate_file(ctx, enccert, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_enc_certificate_file %s failed", enccert);
    printf("load sm2 cert key finish\n");

    // 加载rsa证书
    r = SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_certificate_file %s failed", cert);
    r = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    check1(r <= 0, "SSL_CTX_use_PrivateKey_file %s failed", key);
    printf("load rsa cert key finish\n");

    r = SSL_CTX_check_private_key(ctx);
    check1(!r, "SSL_CTX_check_private_key failed");
    printf("SSL inited\n");
    return ctx;
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

    int tun_fd, option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    int maxfd;
    uint32_t nread, nwrite, plength;
    char buffer[BUFSIZE];
    unsigned char packet[BUFSIZE + HEADER_LEN];
    unsigned int packet_len = sizeof(packet);
    struct sockaddr_in local, remote;
    char remote_ip[16] = ""; /* dotted quad IP string */
    unsigned short int port = PORT;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    int cliserv = -1; /* must be specified on cmd line */
    unsigned long int tap2net = 0, net2tap = 0;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

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

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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

        /* 基于 ctx 产生一个新的 SSL */
        ctx = createClientSslCtx();
        if (ctx = NULL)
        {
            printf("createClientSslCtx() fail\n");
            exit(1);
        }
        printf("createClientSslCtx() success\n");
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock_fd);

        /* 建立 SSL 连接 */
        if (SSL_connect(ssl) == -1)
        {
            perror("SSL_connect()");
            exit(1);
        }
        printf("SSL_connect finish\n");
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
        remotelen = sizeof(remote);
        memset(&remote, 0, remotelen);
        if ((net_fd = accept(sock_fd, (struct sockaddr *)&remote, &remotelen)) < 0)
        {
            perror("accept()");
            exit(1);
        }

        do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
    }

    /* use select() to handle two descriptors at once */
    maxfd = (tun_fd > net_fd) ? tun_fd : net_fd;

    while (1)
    {
        int ret;
        fd_set rd_set;

        FD_ZERO(&rd_set);
        FD_SET(tun_fd, &rd_set);
        FD_SET(net_fd, &rd_set);

        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && errno == EINTR)
        {
            continue;
        }

        if (ret < 0)
        {
            perror("select()");
            exit(1);
        }

        if (FD_ISSET(tun_fd, &rd_set))
        {
            /* data from tun: just read it and write it to the network */
            nread = cread(tun_fd, buffer + HEADER_LEN, BUFSIZE - HEADER_LEN);
            do_debug("TAP2NET %lu: Read %d bytes from the tun interface\n", tap2net, nread);

            tap2net++;

            memcpy(buffer, VPN_LABEL, VPN_LABEL_LEN);
            memcpy(buffer + VPN_LABEL_LEN, RECORD_TYPE_DATA, RECORD_TYPE_LABEL_LEN);
            memcpy(buffer + VPN_LABEL_LEN + RECORD_TYPE_LABEL_LEN, &nread, RECORD_LENGTH_LABEL_LEN);
            // plength = htons(nread);
            // memcpy(buffer + 2, &plength, sizeof(plength));
            nwrite = cwrite(net_fd, buffer, nread + HEADER_LEN);
            if (nwrite != (nread + HEADER_LEN))
            {
                printf("net read len[%d] != tun write len[%d] + HEADER_LEN[%d]\n", nwrite, nread, HEADER_LEN);
            }
            do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
        }

        if (FD_ISSET(net_fd, &rd_set))
        {
            /* data from the network: read it, and write it to the tun interface.
             * We need to read the length first, and then the packet */

            /* Read length */
            nread = read_n(net_fd, buffer, HEADER_LEN);
            if (nread == 0)
            {
                /* ctrl-c at the other end */
                break;
            }
            net2tap++;
            do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

            // plength = ntohs(*((uint16_t *)(buffer + 2)));
            plength = *(uint32_t *)(buffer + VPN_LABEL_LEN + RECORD_TYPE_LABEL_LEN);
            do_debug("NET2TAP %lu: Found %d bytes belong tun\n", net2tap, plength);

            nread = read_n(net_fd, buffer + HEADER_LEN, plength);
            do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

            nwrite = cwrite(tun_fd, buffer + HEADER_LEN, nread);
            if (nwrite != nread)
            {
                printf("tun write len[%d] != net read len[%d]\n", nwrite, nread);
            }
            do_debug("NET2TAP %lu: Written %d bytes to the tun interface\n", net2tap, nwrite);
        }
    }

    return (0);
}

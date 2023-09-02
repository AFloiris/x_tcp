/**
 * 修改重传标志
 *
 * 修改定时器
 *
 */

#include "x_tcp.h"

/* 本次连接所使用的socket_fd */
int TCP_SOCKET = -1;
/* 服务端运行中,以确认建立连接的sock列表 */
x_tcp *established_sock[MAX_SOCK];
/* 服务端运行中,以确认建立连接的sock列表的hash表 */
char ehash[MAX_SOCK] = {0};

/**
 * @brief   创建一个 x_tcp 结构体用于 tcp 通信
 *
 * @param   无
 *
 * @return  初始化的 x_tcp 结构体指针
 *
 * @note
 * 1. 初始化一个 x_tcp 结构体
 * 2. 初始化连接表
 * 3. 创建一个接收 tcp 原始数据包的 socket
 */
x_tcp *x_socket()
{
    /* 初始化结构体 */
    x_tcp *sock = tcp_create();
    sock->state = CLOSED;

    /* 初始化已连接表 */
    for (int i = 0; i < MAX_SOCK; i++) {
        established_sock[i] = NULL;
    }

    /* 创建socket */
    sock->socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    TCP_SOCKET      = sock->socket_fd;

    /* 设置 IP_HERINCL 为1 ，表示数据包自带ip头，无需系统封装 */
    int enable_hdrincl = 1;
    setsockopt(sock->socket_fd, IPPROTO_IP, IP_HDRINCL, &enable_hdrincl, sizeof(enable_hdrincl));
    if (sock->socket_fd < 0) {
        perror("create raw socket error\n");
        exit(-1);
    }
    return sock;
}

/**
 * @brief       绑定需要监听的地址(ip:port)
 *
 * @param sock  用于绑定的 x_tcp
 * @param ip    字符串形式的需要监听的 ip
 * @param port  需要监听的端口
 *
 * @return      0成功其他失败
 *
 * @note
 * 1. 将地址绑定至 x_tcp 中
 * 2. 使用 BPF 过滤器,过滤为只接受目标地址是监听的地址,实现监听指定地址
 */
int x_bind(x_tcp *sock, char *ip, uint16_t port)
{
    int ret;
    /* 将地址绑定在 x_tcp 中 */
    inet_pton(AF_INET, ip, &sock->local_addr.ip);
    sock->local_addr.ip   = ntohl(sock->local_addr.ip);
    sock->local_addr.port = port;
    sock->lhash           = cal_hash(sock->local_addr.ip, port);

    /* 使用 BPF 过滤器 */
    struct sock_filter code[] = {
        {0x20, 0, 0, 0x00000010},             // 获取偏移量为16的字节数据(目标IP)
        {0x15, 0, 6, sock->local_addr.ip},    // 寄存器值与 ip对比,相同执行下一步,不同结束
        {0x28, 0, 0, 0x00000006},             // 获取偏移量为6的字节数据(片偏移)
        {0x45, 3, 0, 0x00001fff},             // 寄存器值与 0x1fff 相与,如果不为0,则这是分片包,直接正确返回,否则下一步
        {0xb1, 0, 0, 0x00000000},             // 4*([0]&0xf),计算出ip头部长度并保存在x寄存器中
        {0x48, 0, 0, 0x00000002},             // 获取偏移量为x+2(22)的字节数据(目标端口)
        {0x15, 0, 1, sock->local_addr.port},  // 寄存器值与 port对比,想用执行下一步,不同结束
        {0x6, 0, 0, 0x00040000},              // 正确返回0x40000
        {0x6, 0, 0, 0x00000000},              // 错误返回0x0
    };
    struct sock_fprog bpf = {
        .len    = sizeof(code) / sizeof(code[0]),
        .filter = code,
    };
    ret = setsockopt(TCP_SOCKET, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    return ret;
}

/**
 * @brief 进入监听的状态
 *
 * @param sock 用于监听的 x_tcp
 *
 * @return 0成功, 其他失败
 *
 * @note
 * 1. 修改 x_tcp 状态
 * 2. 创建一个线程在后台持续接收并处理数据
 */
int x_listen(x_tcp *sock)
{
    int ret;
    /* 状态修改为监听 */
    sock->state = LISTEN;
    /* 创建线程,一直读取socket数据 */
    ret = pthread_create(&sock->recv_pt, NULL, (void *)recv_thread, sock);
    return ret;
}

/**
 * @brief 客户端连接服务端
 *
 * @param sock 需要连接的 x_tcp
 * @param local_ip 字符串形式的本机 ip
 * @param local_port 用于通信的本机端口
 * @param remote_ip  字符串形式的服务器 ip
 * @param remote_port 服务器端口
 *
 * @return 0成功, 其他失败
 *
 * @note
 * 1. 绑定地址信息至 x_tcp
 * 2. 利用BPF过滤,只接受连接的服务端的数据
 * 3. 建一个线程在后台持续接收并处理数据
 * 4. 开始三次握手阶段,发送 seq 包
 * 5. 等待后台线程处理 seq_ack 包 并发送 ack 包后,完成三次握手
 * 6. 将连接成功 x_tcp 放入已连接表中
 * 7. 开启发送线程与重传线程
 */
int *x_connect(x_tcp *sock, char *local_ip, int local_port, char *remote_ip, int remote_port)
{
    /* 绑定本机地址与远程地址 */
    inet_pton(AF_INET, local_ip, &sock->local_addr.ip);
    sock->local_addr.ip   = ntohl(sock->local_addr.ip);
    sock->local_addr.port = local_port;
    inet_pton(AF_INET, remote_ip, &sock->remote_addr.ip);
    sock->remote_addr.ip   = ntohl(sock->remote_addr.ip);
    sock->remote_addr.port = remote_port;
    /* BPF过滤,只接受已绑定的本机地址和远程地址的TCP包 */
    struct sock_filter code[] = {
        {0x20, 0, 0, 0x0000000c},              // 获取偏移量为12的字节数据(源IP)
        {0x15, 0, 10, sock->remote_addr.ip},   // 寄存器值与 ip对比,相同执行下一步,不同结束
        {0x20, 0, 0, 0x00000010},              // 获取偏移量为16的字节数据(目标IP)
        {0x15, 0, 8, sock->local_addr.ip},     // 寄存器值与 ip对比,相同执行下一步,不同结束
        {0x28, 0, 0, 0x00000006},              // 获取偏移量为6的字节数据(片偏移)
        {0x45, 3, 0, 0x00001fff},              // 寄存器值与 0x1fff 相与,如果不为0,则这是分片包,直接正确返回,否则下一步
        {0xb1, 0, 0, 0x00000000},              // 4*([0]&0xf),计算出ip头部长度并保存在x寄存器中
        {0x48, 0, 0, 0x00000000},              // 获取偏移量为x+0(20)的字节数据(源端口)
        {0x15, 0, 3, sock->remote_addr.port},  // 寄存器值与 port对比,想用执行下一步,不同结束
        {0x48, 0, 0, 0x00000002},              // 获取偏移量为x+2(22)的字节数据(目标端口)
        {0x15, 0, 1, sock->local_addr.port},   // 寄存器值与 port对比,想用执行下一步,不同结束
        {0x6, 0, 0, 0x00040000},               // 正确返回0x40000
        {0x6, 0, 0, 0x00000000},               // 错误返回0x0
    };
    struct sock_fprog bpf = {
        .len    = sizeof(code) / sizeof(code[0]),
        .filter = code,
    };
    setsockopt(sock->socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    /* 创建线程,一直读取socket数据 */
    pthread_create(&sock->recv_pt, NULL, (void *)recv_thread, sock);

    /* 发送SYN包 */

#ifdef TCP_DEBUG
    printf("发送第一次握手 SYN 包\n");
#endif

    x_packet *syn_packet = packet_create(sock, CLIENT_CONN_SEQ, 0, SYN, 1, NULL, 0);
    packet_send(sock, syn_packet, 0);
    sock->state = SYN_SENT;

    /* 等待连接成功 */
    while (sock->state != ESTABLISHED) {
    };

    /* 将连接成功的 x_tcp 放入 连接表中 */
    int hashval;
    hashval                   = cal_hash(sock->remote_addr.ip, sock->remote_addr.port);
    ehash[hashval]            = 1;
    established_sock[hashval] = sock;

    /* 启动数据发送线程与数据重传线程 */
    pthread_create(&sock->send_pt, NULL, (void *)send_thread, sock);
    pthread_create(&sock->retran_pt, NULL, (void *)retran_thread, sock);

#ifdef TCP_DEBUG
    printf("连接成功 \n");
#endif

    return 0;
}

/**
 * @brief 接收并返回连接成功的客户端
 *
 * @param sock 需要被连接的 x_tcp, 即服务端 x_tcp
 *
 * @return x_tcp 连接成功的客户端 x_tcp
 *
 * @note
 * 1. 等待查询服务端的已连接队列中,是否有已连接的客户端
 * 2. 将已连接的客户端保存在全局已连接表中
 * 3. 开启发送线程与重传线程
 */
x_tcp *x_accept(x_tcp *sock)
{
    /* 等待查询已连接队列 */
    while (!sock->complete_conn_queue->queue_size) {
    };

    /* 出列 */
    x_tcp *conn_sock = deQueue(sock->complete_conn_queue);

    /* 保存在已连接的hash表中 */
    int hashval;
    hashval                   = cal_hash(conn_sock->remote_addr.ip, conn_sock->remote_addr.port);
    ehash[hashval]            = 1;
    established_sock[hashval] = conn_sock;

    /* 启动数据发送线程与数据重传线程 */
    pthread_create(&conn_sock->send_pt, NULL, (void *)send_thread, conn_sock);
    pthread_create(&conn_sock->retran_pt, NULL, (void *)retran_thread, conn_sock);

#ifdef TCP_DEBUG
    printf("连接成功\n");
#endif

    return conn_sock;
}

/**
 * @brief 写操作函数
 *
 * @param sock 需要发送数据的 x_tcp
 * @param data 需要发送的数据
 * @param len 需要发送的数据长度
 *
 * @return 正数:成功写入的长度; 其他:错误
 *
 * @note
 * 调用 data_to_buffer 将数据写入到 x_tcp 发送缓冲区中
 */
int x_write(x_tcp *sock, const void *data, int len)
{
    char *buf = (char *)malloc(len);
    memcpy(buf, data, len);
    return data_to_buffer(sock, buf, len);
}

/**
 * @brief   读操作函数
 *
 * @param sock  需要读取数据的 x_tcp
 * @param buf   读取数据的缓冲区指针
 * @param len   需要读取的数据长度
 *
 * @return  正数: 读取到的实际数据长度; 其他: 错误
 *
 * @note
 * 1. 阻塞等待缓冲区有数据
 * 2. 读取指定长度数据,并删除指定长度缓冲区数据
 */
int x_read(x_tcp *sock, void *buf, int len)
{
    /* 等待缓冲区有数据 */
    while (sock->received_len <= 0)
        ;
    /* 加锁 */
    while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
        ;

    int read_len = 0;
    /* 从中读取 len 长度的数据 */
    if (sock->received_len >= len) {
        read_len = len;
    }
    /* 读取 sock->received_len 长度的数据(全读出来) */
    else {
        read_len = sock->received_len;
    }
    memcpy(buf, sock->received_buf, read_len);

    /* 如果还有剩余数据,将剩下的重新分配内存保存 */
    if (read_len < sock->received_len) {
        char *new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
    } else {
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }
    pthread_mutex_unlock(&(sock->recv_lock));  // 解锁
    return read_len;
}

/**
 * @brief 关闭 tcp 连接
 *
 * @param sock 需要关闭连接的 x_tcp
 *
 * @return 0: 成功 | 其他: 错误
 *
 * @note
 * 1. 发送第一次挥手的 fin 包,接下来在后台读取线程完成剩下3次挥手
 * 2. 释放 x_tcp
 *
 * @todo 增加服务端的close
 */
int x_close(x_tcp *sock)
{
    while (sock->send_len != 0) {
    };
    if (sock->state == ESTABLISHED) {
        uint32_t  seq    = sock->window.wnd_send->nextseq;
        x_packet *packet = packet_create(sock, seq, 0, FIN, 1, NULL, 0);

#ifdef TCP_DEBUG
        printf("发送第一次挥手 FIN 包\n");
#endif

        packet_send(sock, packet, 0);
        sock->state = FIN_WAIT_1;
    }
    /* 等待四次挥手完成 */
    while (sock->state != CLOSED) {
    };
    memset(sock, 0, sizeof(x_tcp));
    free(sock);

#ifdef TCP_DEBUG
    printf("关闭连接\n");
#endif

    return 0;
}

/**
 * @brief   将用户需要发送的数据放入sock缓冲区
 *
 * @param   sock    需要放入数据的 x_tcp
 * @param   buf     需要放入的数据
 * @param   len     需要放入的数据长度
 *
 * @return  正数: 实际放入的数据的长度  |   其他: 错误
 *
 */
static int data_to_buffer(x_tcp *sock, const char *buf, int len)
{
    int print = 1;
    /* 查询缓冲区大小 */
    while (MAX_TCP_BUF - sock->send_len < len) {
        if (print) {
#ifdef TCP_DEBUG
            printf("缓冲区已满,阻塞等待...\n");
#endif

            print = 0;
        }
    }
    /* 向缓冲区中添加数据 */
    while (pthread_mutex_lock(&(sock->send_lock)) != 0)
        ;
    /* 如果缓冲区为空,则直接分配 */
    if (sock->send_buf == NULL) {
        sock->send_buf = malloc(len);
    }
    /* 不为空,则重新分配内存,添加数据 */
    else {
        sock->send_buf = realloc(sock->send_buf, sock->send_len + len);
    }
    memcpy(sock->send_buf + sock->send_len, buf, len);
    sock->send_len += len;
    pthread_mutex_unlock(&(sock->send_lock));
    return len;
}

/**
 * @brief   后台数据读取线程函数
 *
 * @param   sock    需要读取数据的 x_tcp
 *
 * @return  无
 *
 * @note
 * 1. 持续读取数据
 * 2. 通过数据包中的源 ip 和源 port 计算 hash,判断是否是已连接的 x_tcp
 */
static void *recv_thread(x_tcp *sock)
{
    char     buf[DEFAULT_HEADER_SIZE + MAX_DATA_SIZE];
    uint32_t remote_ip;
    uint16_t remote_port;
    int      hashval;
    /* 读取 socket 数据 */
    while (1) {
        memset(buf, 0, sizeof(buf));
        recv(sock->socket_fd, buf, sizeof(buf), 0);

        /* 获取数据包中源 ip 和源 port ,并计算 hash */
        remote_ip   = get_ip_src_ip(buf);
        remote_port = get_tcp_src_port(buf + DEFAULT_IP_HEADER_SIZE);
        hashval     = cal_hash(remote_ip, remote_port);
        if (ehash[hashval] != 0) {
            packet_handle(established_sock[hashval], buf);
        } else {
            packet_handle(sock, buf);
        }
    }
}

/**
 * @brief   数据包处理函数
 *
 * @param   sock    需要数据包处理的 x_tcp
 * @param   packet  需要处理的数据包
 *
 * @note
 * 1. 通过 sock 的状态,判断当前数据包的处理方式
 * 2. 通过 flags 判断当前数据包的处理方式
 * 3. 通过 ack_seq 判断当前数据包是否正确
 */
static void packet_handle(x_tcp *sock, char *packet)
{
    /* 获取包中属性 */
    uint8_t  pkt_flags   = get_tcp_flags(packet + DEFAULT_IP_HEADER_SIZE);
    uint32_t pkt_seq     = get_tcp_seq(packet + DEFAULT_IP_HEADER_SIZE);
    uint32_t pkt_ack_seq = get_tcp_ack_seq(packet + DEFAULT_IP_HEADER_SIZE);

    /* 如果是 LISTEN 状态(服务端) */
    if (sock->state == LISTEN) {
        /* 接收到第一次握手的 syn 包,发送 syn_ack 包 */
        if (pkt_flags == SYN) {
#ifdef TCP_DEBUG
            printf("收到第一次握手 syn 包\n");
#endif

            x_tcp *conn_sock = tcp_create();

            /* 将连接 x_tcp 的状态改为 SYN_RECV 并存入 LISTEN 状态的 x_tcp (服务端)的半连接队列中 */
            conn_sock->state            = SYN_RECV;
            conn_sock->local_addr.ip    = sock->local_addr.ip;
            conn_sock->local_addr.port  = sock->local_addr.port;
            conn_sock->remote_addr.ip   = get_ip_src_ip(packet);
            conn_sock->remote_addr.port = get_tcp_src_port(packet + DEFAULT_IP_HEADER_SIZE);
            enQueue(sock->incomplete_conn_queue, conn_sock);

            /* 向客户端发送 syn_ack 包 */
            uint32_t  seq            = SERVER_CONN_SEQ;
            uint32_t  ack_seq        = get_tcp_seq(packet + DEFAULT_IP_HEADER_SIZE) + 1;
            x_packet *syn_ack_packet = packet_create(conn_sock, seq, ack_seq, SYN | ACK, 1, NULL, 0);

#ifdef TCP_DEBUG
            printf("发送第二次握手 syn_ack 包\n");
#endif

            packet_send(sock, syn_ack_packet, 0);
            return;
        }
        /* 接收到第三次握手的 ack 包,确认连接 */
        if (pkt_flags == ACK) {
            if (pkt_ack_seq == SERVER_CONN_SEQ + 1) {
/* 三次握手成功,将其 x_tcp 放入已连接队列 */
#ifdef TCP_DEBUG
                printf("收到第三次握手 ack 包\n");
#endif
                x_tcp *conn_sock = deQueue(sock->incomplete_conn_queue);
                conn_sock->state = ESTABLISHED;
                enQueue(sock->complete_conn_queue, conn_sock);
                return;
            } else {
#ifdef TCP_DEBUG
                printf("收到 ack 包,但 ack_seq 错误\n");
#endif
            }
        }
        return;
    }

    /* SYN_SENT 状态,客户端发送了 syn 包,等待服务端的 syn_ack 包 */
    if (sock->state == SYN_SENT) {
        /* ack syn 标志位 */
        if (pkt_flags == (ACK | SYN)) {
            /* 确认序列号正确 */
            if (pkt_ack_seq == CLIENT_CONN_SEQ + 1) {
#ifdef TCP_DEBUG
                printf("收到第二次握手 syn_ack 包\n");
#endif
                uint32_t ack_seq = get_tcp_seq(packet + DEFAULT_IP_HEADER_SIZE) + 1;
/* 发送 ack 包 */
#ifdef TCP_DEBUG
                printf("发送第三次握手 ack 包\n");
#endif
                x_packet *ack_packet = packet_create(sock, CLIENT_CONN_SEQ + 1, ack_seq, ACK, 1, NULL, 0);
                packet_send(sock, ack_packet, 0);
                sock->state = ESTABLISHED;
                return;
            } else {
#ifdef TCP_DEBUG
                printf("收到 syn_ack 包,但 ack_seq 错误\n");
#endif
            }
        }
        return;
    }

    /* ESTABLISHED 连接状态下,接收到的为数据包或 fin 包 */
    if (sock->state == ESTABLISHED) {
        /* 数据包 */
        if (pkt_flags == 0) {
            // 加锁
            while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
                ;
            /* 收到的包的序列号是期待的序列号 */
            if (pkt_seq == sock->window.wnd_recv->expect_seq) {
                uint32_t data_len = get_ip_tot_len(packet) - DEFAULT_HEADER_SIZE;
                /* 把收到的数据放到接收缓冲区 */
                if (MAX_TCP_BUF - sock->received_len < (int)data_len) {  // 缓冲区满
#ifdef TCP_DEBUG
                    printf("接收缓冲区已满 丢弃包\n");
#endif
                    return;
                }
                if (sock->received_buf == NULL) {  // 缓冲区空
                    sock->received_buf = malloc(data_len);
                } else {  // 缓冲区有数据
                    sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
                }
                memcpy(sock->received_buf + sock->received_len, packet + DEFAULT_HEADER_SIZE, data_len);
                sock->received_len += data_len;
                sock->window.wnd_recv->expect_seq = pkt_seq + data_len;

                uint32_t  seq        = sock->window.wnd_send->nextseq;     // 序列号
                uint32_t  ack_seq    = sock->window.wnd_recv->expect_seq;  // 确认序列号
                uint16_t  adv_window = MAX_TCP_BUF - sock->received_len;   // 窗口大小
                x_packet *ack_packet = packet_create(sock, seq, ack_seq, ACK, adv_window, NULL, 0);

#ifdef TCP_DEBUG
                printf("收到seq = %d 的包 发送 ack 包 ack = %d\n", pkt_seq, ack_seq);
#endif

                packet_send(sock, ack_packet, 0);
                pthread_mutex_unlock(&(sock->recv_lock));  // 解锁
                return;
            }
            /* 收到的包的序列号不是期待的序列号 */
            else {
                uint32_t  seq        = sock->window.wnd_send->nextseq;
                uint32_t  ack_seq    = sock->window.wnd_recv->expect_seq;
                uint16_t  adv_window = MAX_TCP_BUF - sock->received_len;
                x_packet *ack_packet = packet_create(sock, seq, ack_seq, ACK, adv_window, NULL, 0);
                packet_send(sock, ack_packet, 0);

#ifdef TCP_DEBUG
                printf("收到seq = %d 的包 [丢弃包] 发送 ack 包 ack = %d\n", pkt_seq, ack_seq);
#endif

                pthread_mutex_unlock(&(sock->recv_lock));  // 解锁
                return;
            }
        }

        /* 收到的是 ack 包 */
        if (pkt_flags == ACK) {
            /* 接收缓冲区加锁 */
            while (pthread_mutex_lock(&(sock->send_lock)) != 0)
                ;
            /* 收到的ack包在发送窗口外 直接丢弃 */
            if (pkt_ack_seq < sock->window.wnd_send->base) {
#ifdef TCP_DEBUG
                printf("收到的 ack 包在发送窗口外 [丢弃包] \n");
#endif

            }
            /* 表示开始收到重复 ack */
            else if (pkt_ack_seq == sock->window.wnd_send->base) {
                /* todo */

#ifdef TCP_DEBUG
                printf("收到 ack 包 ack = %d\n", pkt_ack_seq);
#endif

                sock->window.wnd_send->rwnd = get_tcp_windows(packet + DEFAULT_IP_HEADER_SIZE);

                if (sock->window.wnd_send->congestion_status == SLOW_START || sock->window.wnd_send->congestion_status == CONGESTION_AVOIDANCE) {
                    while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0)
                        ;
                    sock->window.wnd_send->ack_cnt += 1;
                    pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));
                }

                if (sock->window.wnd_send->congestion_status == FAST_RECOVERY) {
                    sock->window.wnd_send->cwnd += MAX_DATA_SIZE;
                }

                if (sock->window.wnd_send->ack_cnt == 3 && sock->window.wnd_send->congestion_status != FAST_RECOVERY) {
                    sock->is_retransing                      = true;
                    sock->window.wnd_send->ssthresh          = sock->window.wnd_send->rwnd / 2;
                    sock->window.wnd_send->cwnd              = sock->window.wnd_send->ssthresh + 3 * MAX_DATA_SIZE;
                    sock->window.wnd_send->congestion_status = FAST_RECOVERY;

#ifdef TCP_DEBUG
                    printf("收到3个重复 ack 开始快速重传\n");
#endif
                }
            }
            /* 收到可用于更新的ACK */
            else {
#ifdef TCP_DEBUG
                printf("收到 ack 包 ack=%d\n", pkt_ack_seq);
#endif

                while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0)
                    ;
                sock->window.wnd_send->ack_cnt = 0;
                pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));

                /* 拥塞窗口算法 TODO */
                if (sock->window.wnd_send->congestion_status == SLOW_START) {
                    sock->window.wnd_send->cwnd += MAX_DATA_SIZE;
                    if (sock->window.wnd_send->cwnd >= sock->window.wnd_send->ssthresh) {
                        sock->window.wnd_send->congestion_status = CONGESTION_AVOIDANCE;
                    }
                } else if (sock->window.wnd_send->congestion_status == CONGESTION_AVOIDANCE) {
                    sock->window.wnd_send->cwnd = sock->window.wnd_send->cwnd + MAX_DATA_SIZE * (MAX_DATA_SIZE / sock->window.wnd_send->cwnd);
                } else if (sock->window.wnd_send->congestion_status == FAST_RECOVERY) {
                    sock->window.wnd_send->cwnd              = sock->window.wnd_send->ssthresh;
                    sock->window.wnd_send->congestion_status = CONGESTION_AVOIDANCE;
                }

                uint32_t free_len = pkt_ack_seq - sock->window.wnd_send->base;
                /* 判断是否可以修改RTT */
                if (sock->window.wnd_send->is_estimating_rtt) {
                    if (sock->window.wnd_send->rtt_expect_ack == pkt_ack_seq) {
                        TimeoutInterval(sock);
                    }
                    sock->window.wnd_send->is_estimating_rtt = false;
                }
                /* 更新窗口 */
                sock->window.wnd_send->base = pkt_ack_seq;
                sock->window.wnd_send->rwnd = get_tcp_windows(packet + DEFAULT_IP_HEADER_SIZE);

                if (sock->window.wnd_send->base == sock->window.wnd_send->nextseq) {
                    stopTimer(sock);
                } else {
                    stopTimer(sock);
                    startTimer(sock);
                }
                /* 更新发送缓冲区 */
                char *new_buf = malloc(sock->send_len - free_len);
                memcpy(new_buf, sock->send_buf + free_len, sock->send_len - free_len);

                free(sock->send_buf);

                sock->send_len -= free_len;
                sock->sent_len -= free_len;
                sock->send_buf = new_buf;

#ifdef TCP_DEBUG
                printf("发送窗口 base=%d, nextseq=%d\n", sock->window.wnd_send->base, sock->window.wnd_send->nextseq);
#endif
#ifdef TCP_DEBUG
                printf("发送缓冲区 send_len=%d, sent_len=%d\n", sock->send_len, sock->sent_len);
#endif
            }

            pthread_mutex_unlock(&(sock->send_lock));  // 解锁

            return;
        }

        /* FIN包 */
        if (pkt_flags == FIN) {
#ifdef TCP_DEBUG
            printf("收到第一次挥手 fin 包\r\n");
#endif
            /* 向客户端发送 ack 包 */
            uint32_t  seq        = sock->window.wnd_send->nextseq;
            uint32_t  ack_seq    = pkt_seq + 1;
            x_packet *ack_packet = packet_create(sock, seq, ack_seq, ACK, 1, NULL, 0);
#ifdef TCP_DEBUG
            printf("发送第二次挥手 ack 包\r\n");
#endif
            packet_send(sock, ack_packet, 0);
            sock->state = CLOSE_WAIT;
            /* 一段时间后,服务端发送 fin 包 */
            sleep(1);
            seq                  = sock->window.wnd_send->nextseq;
            x_packet *fin_packet = packet_create(sock, seq, 0, FIN, 1, NULL, 0);
#ifdef TCP_DEBUG
            printf("发送第三次挥手 FIN 包\n");
#endif
            packet_send(sock, fin_packet, 0);
            sock->state = LAST_ACK;
        }
        return;
    }

    /* FIN_WAIT_1 状态, 已发送 fin 包,等待接收 ack 包 */
    if (sock->state == FIN_WAIT_1) {
        if (pkt_flags == ACK) {
#ifdef TCP_DEBUG
            printf("收到第二次挥手 ack 包\n");
#endif
            sock->state = FIN_WAIT_2;
        }
        return;
    }

    /* FIN_WAIT_2 状态,等待对方发送 fin 包 */
    if (sock->state == FIN_WAIT_2) {
        if (pkt_flags == FIN) {
#ifdef TCP_DEBUG
            printf("收到第三次挥手 fin 包\n");
#endif
            uint32_t  seq        = sock->window.wnd_send->nextseq;
            uint32_t  ack_seq    = pkt_seq + 1;
            x_packet *ack_packet = packet_create(sock, seq, ack_seq, ACK, 1, NULL, 0);
#ifdef TCP_DEBUG
            printf("发送第四次挥手 ack 包\n");
#endif
            packet_send(sock, ack_packet, 0);
            sock->state = TIME_WAIT;
            sleep(1);
            sock->state = CLOSED;
        }
        return;
    }

    /* LAST_ACK 状态, 等待客户端发送 ack 包,完成四次挥手,删除客户端的 x_tcp */
    if (sock->state == LAST_ACK) {
        if (pkt_flags == ACK) {
#ifdef TCP_DEBUG
            printf("收到第四次挥手 ACK 包\n");
#endif

            pthread_cancel(sock->send_pt);
            pthread_cancel(sock->retran_pt);
            int hashval               = cal_hash(sock->remote_addr.ip, sock->remote_addr.port);
            ehash[hashval]            = 0;
            established_sock[hashval] = NULL;
            sock->state               = CLOSED;
            free(sock);
            return;
        }
    }
}

/**
 * @brief   后台数据发送线程函数
 *
 * @param   sock    需要数据发送的 x_tcp
 *
 * @note
 * 将 sock 的数据发送缓冲区的数据发送
 */
static void *send_thread(x_tcp *sock)
{
#ifdef TCP_DEBUG
    printf("启动发送线程\n");
#endif
    while (1) {
        /**
         * 待发送缓冲区中还有数据 sent_len < send_len
         * 没有在重传 !is_retransing
         * 发送窗口还有剩余序列号   nextseq < base + win_size
         * */
        
        if (sock->sent_len < sock->send_len &&
            !sock->is_retransing &&
            sock->window.wnd_send->nextseq < sock->window.wnd_send->base + sock->window.wnd_send->window_size) {
            /* 给发送缓冲区加锁 */
            while (pthread_mutex_lock(&(sock->send_lock)) != 0)
                ;
            uint32_t wnd_base = sock->window.wnd_send->base;         // 当前窗口的首序列号
            uint32_t wnd_size = sock->window.wnd_send->window_size;  // 当前窗口大小
            uint32_t wnd_next = sock->window.wnd_send->nextseq;      // 下一个数据包的序列号

            uint32_t buf_len      = sock->send_len;               // 需要发送的数据大小
            uint32_t buf_sent_len = sock->sent_len;               // 已发送的数据大小
            uint16_t rwnd         = sock->window.wnd_send->rwnd;  // 接收窗口大小
            uint16_t cwnd         = sock->window.wnd_send->cwnd;  // 拥塞窗口大小
            /* 需发送的数据 小于 发送窗口剩余的大小 */
            if (buf_len - buf_sent_len <= wnd_base + wnd_size - wnd_next) {
                /* 需发送的数据大于 MAX_DATA_SIZE */
                while (buf_len - buf_sent_len > MAX_DATA_SIZE &&
                       wnd_next + MAX_DATA_SIZE - wnd_base <= min(cwnd, rwnd)) {
                    uint32_t seq  = wnd_next;
                    char    *data = malloc(MAX_DATA_SIZE);
                    memcpy(data, sock->send_buf + buf_sent_len, MAX_DATA_SIZE);
                    x_packet *pkt = packet_create(sock, seq, 0, 0, 1, data, MAX_DATA_SIZE);

#ifdef TCP_DEBUG
                    printf("发送 %d 字节大小的包 seq = %d\n", MAX_DATA_SIZE, seq);
#endif

                    packet_send(sock, pkt, MAX_DATA_SIZE);

                    /* 测试计算RTT */
                    if (sock->window.wnd_send->is_estimating_rtt == false) {
                        sock->window.wnd_send->is_estimating_rtt = true;
                        gettimeofday(&sock->window.wnd_send->send_time, NULL);
                        sock->window.wnd_send->rtt_expect_ack = seq + MAX_DATA_SIZE;
                    }

                    /* 如果发送窗口的base和nextseq一样 说明是窗口的第一个 为其启动计时器 */
                    if (wnd_base == wnd_next) {
                        startTimer(sock);
                    }
                    wnd_next += MAX_DATA_SIZE;      // 发送完数据,更新下一个数据包的序列号
                    buf_sent_len += MAX_DATA_SIZE;  // 更新已发送数据的大小
                }

                /* 需要发送的数据小于 MAX_DATA_SIZE */
                uint32_t seq = wnd_next;                // 序列号
                uint32_t len = buf_len - buf_sent_len;  // 数据长度
                if (wnd_next + len - wnd_base <= min(cwnd, rwnd)) {
                    /* 发送数据 */
                    char *data = malloc(len);
                    memcpy(data, sock->send_buf + buf_sent_len, len);              // 复制数据
                    x_packet *pkt = packet_create(sock, seq, 0, 0, 1, data, len);  // 创建包

#ifdef TCP_DEBUG
                    printf("发送 %d 字节大小的包 seq = %d\n", len, seq);
#endif

                    packet_send(sock, pkt, len);

                    /* 测试计算RTT */
                    if (sock->window.wnd_send->is_estimating_rtt == false) {
                        sock->window.wnd_send->is_estimating_rtt = true;
                        gettimeofday(&sock->window.wnd_send->send_time, NULL);
                        sock->window.wnd_send->rtt_expect_ack = seq + len;
                    }
                    /* 如果发送窗口的base和nextseq一样 说明是窗口的第一个 为其启动计时器 */
                    if (wnd_base == wnd_next) {
                        startTimer(sock);
                    }
                    wnd_next += len;      // 发送完数据,更新下一个数据包的序列号
                    buf_sent_len += len;  // 更新已发送数据的大小
                }

                /* 发送完数据,更新 sock 中的 window 数据 */
                sock->window.wnd_send->nextseq = wnd_next;
                sock->sent_len                 = buf_sent_len;

                pthread_mutex_unlock(&(sock->send_lock));  // 解锁
            }

            /* 需发送的数据 大于 发送窗口剩余的大小 TODO */
            if (buf_len - buf_sent_len > wnd_base + wnd_size - wnd_next) {
                /* 需发送窗口可用的序列号大于 MAX_DATA_SIZE */
                while (wnd_base + wnd_size - wnd_next > MAX_DATA_SIZE &&
                       wnd_next + MAX_DATA_SIZE - wnd_base <= min(cwnd, rwnd)) {
                    /* 发送数据 */
                    uint32_t seq  = wnd_next;
                    char    *data = malloc(MAX_DATA_SIZE);
                    memcpy(data, sock->send_buf + buf_sent_len, MAX_DATA_SIZE);
                    x_packet *pkt = packet_create(sock, seq, 0, 0, 1, data, MAX_DATA_SIZE);
                    packet_send(sock, pkt, MAX_DATA_SIZE);
                    /* 启动定时器 */
                    if (wnd_base == wnd_next) {
                        startTimer(sock);
                    }
                    wnd_next += MAX_DATA_SIZE;
                    buf_sent_len += MAX_DATA_SIZE;

#ifdef TCP_DEBUG
                    printf("发送 %d 字节大小的包 seq = %d\n", MAX_DATA_SIZE, seq);
#endif
                }

                uint32_t seq = wnd_next;
                uint32_t len = wnd_base + wnd_size - wnd_next;
                if (wnd_next + len - wnd_base <= min(cwnd, rwnd)) {
                    char *data = malloc(len);
                    memcpy(data, sock->send_buf + buf_sent_len, len);
                    x_packet *pkt = packet_create(sock, seq, 0, 0, 1, data, len);
                    packet_send(sock, pkt, len);

#ifdef TCP_DEBUG
                    printf("发送 %d 字节大小的包 seq = %d\n", len, seq);
#endif

                    if (wnd_base == wnd_next) {
                        startTimer(sock);
                    }

                    wnd_next += len;
                    buf_sent_len += len;
                }

                sock->window.wnd_send->nextseq = wnd_next;
                sock->sent_len                 = buf_sent_len;

                pthread_mutex_unlock(&(sock->send_lock));  // 解锁
            }
        }
    }
}

/**
 * @brief   后台数据重传线程函数
 *
 * @param   sock    需要重传处理的 x_tcp
 *
 * @note
 * 通过重传标志判断是否需要重传
 */
static void *retran_thread(x_tcp *sock)
{
#ifdef TCP_DEBUG
    printf("启动数据重传线程\n");
#endif

    while (1) {
        /* 如果需要重传 */
        if (sock->is_retransing) {
            while (pthread_mutex_lock(&(sock->send_lock)) != 0)
                ;  // 给发送缓冲区加锁

#ifdef TCP_DEBUG
            printf("进入重传函数\n");
#endif

            /* 如果超时,修改阻塞窗口大小 */
            if (sock->time.is_timeout) {
                sock->window.wnd_send->ssthresh = sock->window.wnd_send->cwnd / 2;
                sock->window.wnd_send->cwnd     = MAX_DATA_SIZE;
                while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0)
                    ;
                sock->window.wnd_send->ack_cnt = 0;
                pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));
                sock->window.wnd_send->congestion_status = SLOW_START;
            }

            uint32_t retrans_base     = 0;
            uint32_t retransed_size   = 0;
            uint32_t wnd_base         = sock->window.wnd_send->base;
            uint32_t wnd_next         = sock->window.wnd_send->nextseq;
            uint32_t wnd_retrans_size = wnd_next - wnd_base;
            /* 第一次重传 */
            if (sock->last_retrans_size == 0) {
                printf("第一次重传\n");
                sock->last_retrans_seq = wnd_next;
                sock->last_retrans_size++;
            }
            /* 重传同一条消息 */
            else if (sock->last_retrans_seq == wnd_next) {
                /* 重传次数过多 */
                if (sock->last_retrans_size > MAX_RETRANS_SIZE) {
                    printf("重传次数过多,强制断开连接\n");
                    pthread_cancel(sock->send_pt);
                    int hashval               = cal_hash(sock->remote_addr.ip, sock->remote_addr.port);
                    ehash[hashval]            = 0;
                    established_sock[hashval] = NULL;
                    sock->state               = CLOSED;
                    free(sock);
                    pthread_exit(NULL);
                } else {
                    printf("重传同一条消息\n");
                    sock->last_retrans_size++;
                }
            }
            /* 重传另一条消息 */
            else {
                printf("重传另一条消息\n");
                sock->last_retrans_seq  = wnd_next;
                sock->last_retrans_size = 1;
            }

#ifdef TCP_DEBUG
            printf("发送窗口 base=%d, nextseq=%d\n", sock->window.wnd_send->base, sock->window.wnd_send->nextseq);
#endif
#ifdef TCP_DEBUG
            printf("发送缓冲区 send_len=%d, sent_len=%d\n", sock->send_len, sock->sent_len);
#endif

            /* 需发送的数据大于 MAX_DATA_SIZE */
            while (wnd_retrans_size > MAX_DATA_SIZE) {
                uint32_t seq  = wnd_base + retransed_size;
                char    *data = malloc(MAX_DATA_SIZE);
                memcpy(data, sock->send_buf + retransed_size, MAX_DATA_SIZE);
                x_packet *ret_packet = packet_create(sock, seq, 0, 0, 1, data, MAX_DATA_SIZE);
                packet_send(sock, ret_packet, 0);
                if (retrans_base == retransed_size) {
                    startTimer(sock);
                }
                retransed_size += MAX_DATA_SIZE;
                wnd_retrans_size -= MAX_DATA_SIZE;

#ifdef TCP_DEBUG
                printf("重传 %d 大小的包 seq = %d\n", MAX_DATA_SIZE, seq);
#endif
            }

            uint32_t seq = wnd_base + retransed_size;
            uint32_t len = wnd_retrans_size;

            if (len != 0) {
                char *data = malloc(len);
                memcpy(data, sock->send_buf + retransed_size, len);
                x_packet *ret_packet = packet_create(sock, seq, 0, 0, 1, data, MAX_DATA_SIZE);
                packet_send(sock, ret_packet, 0);
                if (retrans_base == retransed_size) {
                    startTimer(sock);
                }

                retransed_size += len;
                wnd_retrans_size -= len;

#ifdef TCP_DEBUG
                printf("重传 %d 大小的包<%s> seq = %d\n", len, data, seq);
#endif
            }

            sock->time.is_timeout = false;
            sock->is_retransing   = false;

            pthread_mutex_unlock(&(sock->send_lock));  // 解锁
        }
    }
}

/**
 * @brief   创建 ip_tcp 包
 *
 * @param   sock        需要进行通信的 x_tcp,主要读取其中的地址属性
 * @param   seq         tcp 头部的序列号
 * @param   ack_seq     tcp 头部的确认序列号
 * @param   flags       tcp 头部的标志位
 * @param   window_size tcp 头部窗口大小
 * @param   data        需要发送的数据
 * @param   len         需要发送的数据长度
 *
 * @return  构建好的数据包指针
 *
 * @note    填充 ip tcp 头部信息
 */
static x_packet *packet_create(x_tcp *sock, uint32_t seq, uint32_t ack_seq, uint16_t flags, uint16_t window_size, char *data, int len)
{
    x_packet *packet = (x_packet *)malloc(sizeof(x_packet));

    packet->ip_header.ihl      = 5;                            // IP头部长度，单位为32位字
    packet->ip_header.version  = 4;                            // IPv4
    packet->ip_header.tos      = 0;                            // 服务类型
    packet->ip_header.tot_len  = htons(40 + len);              // IP包总长度
    packet->ip_header.id       = htons(1234);                  // 标识字段
    packet->ip_header.frag_off = 0;                            // 分段偏移
    packet->ip_header.ttl      = 255;                          // 存活时间
    packet->ip_header.protocol = IPPROTO_TCP;                  // 上层协议为TCP
    packet->ip_header.check    = 0;                            // 校验和
    packet->ip_header.saddr    = htonl(sock->local_addr.ip);   // 源IP地址
    packet->ip_header.daddr    = htonl(sock->remote_addr.ip);  // 目标IP地址

    packet->tcp_header.source  = htons(sock->local_addr.port);   // 源端口号
    packet->tcp_header.dest    = htons(sock->remote_addr.port);  // 目标端口号
    packet->tcp_header.seq     = htonl(seq);                     // 初始化服务端序列号
    packet->tcp_header.ack_seq = htonl(ack_seq);                 // 确认号为第一次握手序列号+1
    packet->tcp_header.doff    = sizeof(struct tcphdr) / 4;      // TCP头部长度，单位为32位字

    packet->tcp_header.urg    = (flags >> 5) & 0x01;
    packet->tcp_header.ack    = (flags >> 4) & 0x01;
    packet->tcp_header.psh    = (flags >> 3) & 0x01;
    packet->tcp_header.rst    = (flags >> 2) & 0x01;
    packet->tcp_header.syn    = (flags >> 1) & 0x01;
    packet->tcp_header.fin    = flags & 0x01;
    packet->tcp_header.window = htons(10000);  // 窗口大小
    packet->tcp_header.check  = 0;             // 校验和

    packet->data = data;
}

/**
 * @brief   发送 ip_tcp 包
 *
 * @param   sock    需要进行发送的 x_tcp
 * @param   packet  需要发送的包
 * @param   len     需要发送的包中,数据的长度
 *
 * @return  正数: 发送数据的长度    |   其他: 错误
 *
 * @note
 * 1. 将包中的数据序列化
 * 2. 通过 sendto 函数发送,目标地址就在包中
 * 3. 释放包的内存
 */
static int packet_send(x_tcp *sock, x_packet *packet, int len)
{
    /* 序列化 */
    char *buf = (char *)malloc(DEFAULT_HEADER_SIZE + len);
    memcpy(buf, packet, DEFAULT_HEADER_SIZE);
    if (len > 0) {
        memcpy(buf + DEFAULT_HEADER_SIZE, packet->data, len);
    }

    /* 发送 */
    int                ret;
    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_port        = packet->tcp_header.dest;
    addr.sin_addr.s_addr = packet->ip_header.daddr;
    ret                  = sendto(TCP_SOCKET, buf, DEFAULT_HEADER_SIZE + len, 0, (struct sockaddr *)&addr, sizeof(addr));
    /* 释放 */
    memset(packet, 0, sizeof(x_packet));
    free(packet);
    free(buf);
    return ret;
}

/****************************** 以下是超时计时器相关函数 ******************************/

/**
 * @brief   超时回调函数,标志重传和超时
 *
 * @param   sv   定时器附带的数据
 */
static void timeout_handler(union sigval sv)
{
    x_tcp *sock = (x_tcp *)sv.sival_ptr;
    printf("超时!!!\n");
    sock->is_retransing   = true;
    sock->time.is_timeout = true;
}

/**
 * @brief   设置超时定时器
 *
 * @param   sock    需要设置定时器的 x_tcp
 */
static void startTimer(x_tcp *sock)
{
    /* 启动定时器*/
    sock->time.its.it_value.tv_sec     = 0;
    sock->time.its.it_value.tv_nsec    = 800000000;
    sock->time.its.it_interval.tv_sec  = 0;
    sock->time.its.it_interval.tv_nsec = 0;
    if (timer_settime(sock->time.timer_id, 0, &sock->time.its, NULL) == -1) {
        perror("timer_settime");
        exit(1);
    }
}

/**
 * @brief   停止定时器
 */
static void stopTimer(x_tcp *sock)
{
    sock->time.its.it_value.tv_sec     = 0;
    sock->time.its.it_value.tv_nsec    = 0;
    sock->time.its.it_interval.tv_sec  = 0;
    sock->time.its.it_interval.tv_nsec = 0;
    if (timer_settime(sock->time.timer_id, 0, &sock->time.its, NULL) == -1) {
        perror("timer_settime");
        exit(1);
    }

#ifdef TCP_DEBUG
    printf("停止定时器\n");
#endif
}

/**
 * @brief 往返时间评估,并设置 x_tcp RTT
 *
 * @param   sock    需要评估的 sock
 *
 * @return  无
 *
 * @note
 * 1. EstimatedRTT = (1-α) * EstimatedRTT + α * SampleRTT （ α推荐值是α=0.125）
 * 2. DevRTT = (1-β) * DevRTT + β * (SampleRTT - EstimatedRTT) （β推荐值为0.25）
 * 3. TimeoutInterval = EstimatedRTT + 4 * DevRTT
 *
 */
static void TimeoutInterval(x_tcp *sock)
{
    struct timeval send_time = sock->window.wnd_send->send_time;
    struct timeval local_time;
    gettimeofday(&local_time, NULL);

    long sampleRTT = (local_time.tv_sec - send_time.tv_sec) * 1000000 + (local_time.tv_usec - send_time.tv_usec);

#ifdef TCP_DEBUG
    printf("sampleRTT = %ld \n", sampleRTT);
#endif

    sock->window.wnd_send->estmated_rtt = 0.875 * sock->window.wnd_send->estmated_rtt + 0.125 * sampleRTT;

    int abs;

    if (sampleRTT >= sock->window.wnd_send->estmated_rtt) {
        abs = sampleRTT - sock->window.wnd_send->estmated_rtt;
    } else {
        abs = sock->window.wnd_send->estmated_rtt - sampleRTT;
    }

    sock->window.wnd_send->dev_rtt = 0.75 * sock->window.wnd_send->dev_rtt + 0.25 * abs;

    sock->window.wnd_send->timeout.it_value.tv_usec = sock->window.wnd_send->estmated_rtt + 4 * sock->window.wnd_send->dev_rtt;

#ifdef TCP_DEBUG
    printf("------------------------------- TimeoutInterval -------------------------------\n");
#endif
#ifdef TCP_DEBUG
    printf("发送pkt 获取的秒时间 = %ld  获取的微秒时间 = %ld\n", send_time.tv_sec, send_time.tv_usec);
#endif
#ifdef TCP_DEBUG
    printf("收到ack 获取的秒时间 = %ld  获取的微秒时间 = %ld\n", local_time.tv_sec, local_time.tv_usec);
#endif
#ifdef TCP_DEBUG
    printf("TimeOut = %ld \n", sock->window.wnd_send->timeout.it_value.tv_usec);
#endif
#ifdef TCP_DEBUG
    printf("-------------------------------------------------------------------------------\n");
#endif
}

/****************************** 以下是对socket队列的操作 ******************************/

/**
 * @brief   创建一个空队列
 *
 * @param   无
 *
 * @return  队列指针
 *
 * @note    无
 */
static x_sock_queue *createQueue()
{
    x_sock_queue *q = (x_sock_queue *)malloc(sizeof(x_sock_queue));
    q->front = q->rear = NULL;
    q->queue_size      = 0;
    return q;
}

/**
 * @brief   创建一个队列结点
 *
 * @param   sock    需要变成节点的 x_tcp
 *
 * @return  节点指针
 *
 * @note    无
 */
static x_sock_node *newNode(x_tcp *sock)
{
    x_sock_node *temp = (x_sock_node *)malloc(sizeof(x_sock_node));
    temp->sock        = sock;
    temp->next        = NULL;
    return temp;
}

/**
 * @brief   入队操作
 *
 * @param   q       需要入队的队列
 * @param   sock    需要入队的 x_tcp
 *
 * @return  无
 *
 * @note    无
 */
static void enQueue(x_sock_queue *q, x_tcp *sock)
{
    struct x_sock_node *temp = newNode(sock);

    if (q->rear == NULL) {
        q->front = q->rear = temp;
        q->queue_size++;
        return;
    }

    q->rear->next = temp;
    q->rear       = temp;
    q->queue_size++;
    return;
}

/**
 * @brief   出队操作
 *
 * @param   q       需要出队的队列
 *
 * @return  x_tcp   出队的 x_tcp
 *
 * @note    无
 */
static x_tcp *deQueue(x_sock_queue *q)
{
    if (q->front == NULL)
        return NULL;

    x_sock_node *temp = q->front;
    x_tcp       *sock = temp->sock;
    q->front          = q->front->next;
    q->queue_size--;
    if (q->front == NULL)
        q->rear = NULL;

    memset(temp, 0, sizeof(x_sock_node));
    free(temp);

    return sock;
}

/**
 * @brief   计算 x_tcp 的 hash 值
 *
 * @param   remote_ip   x_tcp 中的 remote_ip 远程 ip
 * @param   remote_port x_tcp 中的 remote_ip 远程 端口
 *
 * @return  hash 值
 *
 * @note
 * linux内核采用的是五元组:src_ip,dest_ip,src_port,src_port,protocol
 */
static int cal_hash(uint32_t remote_ip, uint16_t remote_port)
{
    return abs((remote_ip * 7 + remote_port * 17) % MAX_SOCK);
}

/**
 * @brief   创建一个 x_tcp 结构体
 *
 * @param   无
 *
 * @return  初始化的 x_tcp 结构体指针
 *
 * @note    将 x_tcp 结构体中的属性都赋予初始默认值
 *
 */
static x_tcp *tcp_create()
{
    /* 初始化结构体 */
    x_tcp *sock = (x_tcp *)malloc(sizeof(x_tcp));
    memset(sock, 0, sizeof(x_tcp));
    sock->state     = CLOSED;
    sock->socket_fd = -1;

    /* 初始化锁 */
    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->send_buf = NULL;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;

    if (pthread_cond_init(&sock->wait_cond, NULL) != 0) {
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    /* 初始化发送窗口 */
    sock->window.wnd_send              = malloc(sizeof(x_send_window));
    sock->window.wnd_send->base        = 1;
    sock->window.wnd_send->nextseq     = 1;
    sock->window.wnd_send->window_size = TCP_SENDWN_SIZE;
    pthread_mutex_init(&(sock->window.wnd_send->ack_cnt_lock), NULL);
    sock->window.wnd_send->ack_cnt                     = 0;
    sock->window.wnd_send->cwnd                        = MAX_DATA_SIZE;
    sock->window.wnd_send->rwnd                        = MAX_TCP_BUF;
    sock->window.wnd_send->congestion_status           = SLOW_START;
    sock->window.wnd_send->ssthresh                    = 10 * MAX_DATA_SIZE;
    sock->window.wnd_send->timeout.it_value.tv_sec     = 0;
    sock->window.wnd_send->timeout.it_value.tv_usec    = 800000;
    sock->window.wnd_send->timeout.it_interval.tv_sec  = 0;
    sock->window.wnd_send->timeout.it_interval.tv_usec = 0;
    sock->window.wnd_send->dev_rtt                     = 0;
    sock->window.wnd_send->estmated_rtt                = 0;
    sock->window.wnd_send->is_estimating_rtt           = false;

    // 初始化接收窗口
    sock->window.wnd_recv             = malloc(sizeof(x_send_window));
    sock->window.wnd_recv->expect_seq = 1;

    /* 初始化队列 */
    sock->complete_conn_queue   = createQueue();  // 创建全连接队列
    sock->incomplete_conn_queue = createQueue();  // 创建半连接队列

    // 重传状态
    sock->is_retransing = false;

    /* 初始化定时器 */
    sock->time.is_timeout                  = false;
    sock->time.sev.sigev_notify            = SIGEV_THREAD;
    sock->time.sev.sigev_value.sival_ptr   = sock;
    sock->time.sev.sigev_notify_function   = timeout_handler;
    sock->time.sev.sigev_notify_attributes = NULL;
    if (timer_create(CLOCK_REALTIME, &sock->time.sev, &sock->time.timer_id) == -1) {
        perror("timer_create");
        exit(1);
    }
    sock->time.its.it_value.tv_sec     = 0;
    sock->time.its.it_value.tv_nsec    = 800000000;
    sock->time.its.it_interval.tv_sec  = 0;
    sock->time.its.it_interval.tv_nsec = 0;
}
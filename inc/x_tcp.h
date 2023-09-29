#ifndef _X_TCP_H_
#define _X_TCP_H_

#include <arpa/inet.h>
#include <linux/filter.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "x_packet.h"

#define min(a, b) (((a) < (b)) ? (a) : (b))

/* TCP socket 状态定义 */
#define CLOSED 0
#define LISTEN 1
#define SYN_SENT 2
#define SYN_RECV 3
#define ESTABLISHED 4
#define FIN_WAIT_1 5
#define FIN_WAIT_2 6
#define CLOSE_WAIT 7
#define CLOSING 8
#define LAST_ACK 9
#define TIME_WAIT 10

/* TCP包中的标志位 */
#define FIN 0x01
#define SYN 0x02
#define PST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20

/* 最大sock连接数 */
#define MAX_SOCK 32
/* TCP 最大携带数据大小 */
#define MAX_DATA_SIZE 1375
/* sock 缓冲区大小 */
#define MAX_TCP_BUF 16 * MAX_DATA_SIZE
/* TCP 发送窗口大小 */
#define TCP_SENDWN_SIZE 8 * MAX_DATA_SIZE
/* 最大重传次数 */
#define MAX_RETRANS_SIZE 5

/* TCP 拥塞控制状态 */
#define SLOW_START 0
#define CONGESTION_AVOIDANCE 1
#define FAST_RECOVERY 2

/* 服务端序列号 */
#define SERVER_CONN_SEQ 1234
/* 客户端序列号 */
#define CLIENT_CONN_SEQ 4321

/* tcp/ip 头部大小 */
#define DEFAULT_IP_HEADER_SIZE 20
#define DEFAULT_TCP_HEADER_SIZE 20
#define DEFAULT_HEADER_SIZE (DEFAULT_IP_HEADER_SIZE + DEFAULT_TCP_HEADER_SIZE)

/* TCP用到的各种数据 */
typedef struct x_sock x_sock;
/* tcp 通信的数据包 */
typedef struct x_packet x_packet;
/* 队列结点的结构体定义 */
typedef struct x_sock_node x_sock_node;
/* 队列的结构体定义(未完成队列和已完成队列) */
typedef struct x_sock_queue x_sock_queue;
/* 保存地址端口 */
typedef struct x_sockaddr x_sockaddr;
/* tcp 窗口相关 */
typedef struct x_window      x_window;
typedef struct x_send_window x_send_window;
typedef struct x_recv_window x_recv_window;
/* 定时器相关 */
typedef struct x_time x_time;
x_sock               *x_socket();
int                   x_bind(x_sock *sock, char *ip, uint16_t port);
int                   x_listen(x_sock *sock);
x_sock               *x_accept(x_sock *sock);
int                  *x_connect(x_sock *sock, char *local_ip, int local_port, char *remote_ip, int remote_port);
int                   x_close(x_sock *sock);
int                   x_read(x_sock *sock, void *buf, int len);
int                   x_write(x_sock *sock, const void *data, int len);
int                   x_close(x_sock *sock);

static int data_to_buffer(x_sock *sock, const char *buf, int len);

static void *recv_thread(x_sock *sock);
static void *send_thread(x_sock *sock);
static void *retran_thread(x_sock *sock);

static void      packet_handle(x_sock *sock, char *packet);
static x_packet *packet_create(x_sock *sock, uint32_t seq, uint32_t ack_seq, uint16_t flags, uint16_t window_size, char *data, int len);
static int       packet_send(x_sock *sock, x_packet *packet, int len);

static void timeout_handler(union sigval sv);
static void startTimer(x_sock *sock);
static void stopTimer(x_sock *sock);
static void TimeoutInterval(x_sock *sock);

static x_sock_queue *createQueue();
static x_sock_node  *newNode(x_sock *sock);
static void          enQueue(x_sock_queue *q, x_sock *sock);
static x_sock       *deQueue(x_sock_queue *q);

static int     cal_hash(uint32_t remote_ip, uint16_t remote_port);
static x_sock *sock_create();
static void    sock_delete(x_sock *sock);

/* 保存地址端口 */
struct x_sockaddr {
    uint32_t ip;
    uint16_t port;
};

/* 队列结点的结构体定义 */
struct x_sock_node {
    x_sock      *sock;  // 数据域 存放的是socket
    x_sock_node *next;  // 指向队列的下一个节点
};

/* 队列的结构体定义(未完成队列和已完成队列) */
struct x_sock_queue {
    x_sock_node *front, *rear;
    int          queue_size;
};
// TCP 发送窗口
struct x_send_window {
    uint16_t         window_size;        // 窗口大小
    uint32_t         base;               // 当前窗口的首序列号
    uint32_t         nextseq;            // 当前窗口下一个数据包的序列号
    uint64_t         estmated_rtt;       // 估算往返时间
    uint64_t         dev_rtt;            // 偏差往返时间
    int              ack_cnt;            // 已收到ACK数量
    uint32_t         last_ack;           // 最后一次收到的 ACK 号
    pthread_mutex_t  ack_cnt_lock;       // ACK互斥锁
    struct itimerval timeout;            // 数据包计时器
    uint16_t         rwnd;               // 接收窗口大小,表示接收方允许发送方发送的数据量
    int              congestion_status;  // 拥塞状态
    uint16_t         cwnd;               // 拥塞窗口大小
    uint16_t         ssthresh;           // 慢启动门限
    bool             is_estimating_rtt;  // 来表明是否测量SampleRTT
    struct timeval   send_time;          // 记录发送时间
    uint32_t         rtt_expect_ack;     // 用来测量RTT的报文期待的ACK号
};

// TCP 接受窗口
struct x_recv_window {
    uint32_t expect_seq;  // 预期序列号
};

struct x_window {
    x_send_window *wnd_send;
    x_recv_window *wnd_recv;
};

struct x_time {
    timer_t           timer_id;
    struct sigevent   sev;
    struct itimerspec its;
    bool              is_timeout;
};

/**
 * TCP用到的各种数据
 */
struct x_sock {
    int state;      // tcp的状态
    int socket_fd;  // 连接所用的socket

    pthread_t recv_pt;    // 接收tcp数据包的线程
    pthread_t send_pt;    // 发送TCP消息的线程
    pthread_t retran_pt;  // 消息重传的线程

    x_sockaddr local_addr;                         // 本机的IP和端口
    char       lhash;                              // 本机sock hsh表
    x_sockaddr remote_addr;                        // 远程的IP和端口
    x_sockaddr established_remote_addr[MAX_SOCK];  // 存放建立连接后 连接对方的 IP和端口
    char       ehash[MAX_SOCK];                    // 已连接的sock hash表

    pthread_mutex_t send_lock;  // 发送数据锁
    char           *send_buf;   // 需要发送数据缓存区起始地址
    int             send_len;   // 需要发送数据缓存长度
    int             sent_len;   // 已发送数据的长度

    pthread_mutex_t recv_lock;     // 接收数据锁
    char           *received_buf;  // 接收数据缓存区
    int             received_len;  // 接收数据缓存长度

    pthread_cond_t wait_cond;  // 可以被用来唤醒recv函数调用时等待的线程

    x_window window;  // 发送和接受窗口

    uint32_t last_retrans_seq;   // 上一次重传的序列号
    uint8_t  last_retrans_size;  // 相同数据重传次数
    bool     is_retransing;      // 表明是否在重传

    x_sock_queue *incomplete_conn_queue;  // 半连接队列
    x_sock_queue *complete_conn_queue;    // 全连接队列

    x_time time;
};

/* tcp 通信的数据包 */
struct x_packet {
    struct iphdr  ip_header;
    struct tcphdr tcp_header;
    char         *data;
};

#endif  // !_X_TCP_H_
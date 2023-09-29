#include "x_tcp.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1234

#define CLOSE_MASK ":close"
#define HEARTBEAT_MASK "AaZzheartbeat"
#define HEARTBEAT_TIME 5

/**
 * 保存已连接的 x_sock 的各个信息的节点
 */
typedef struct sock_node sock_node;
struct sock_node {
    pthread_t         recv_pt, heartbeat_pt;
    x_sock*           sock;
    char*             ip;
    struct itimerspec its;
    sock_node *       prev, *next;
    int               is_heartbeat_normal;
};

/* 信息节点链表 */
typedef struct sock_node_list sock_node_list;
struct sock_node_list {
    sock_node *     front, *back;
    int             size;
    pthread_mutex_t lock;
}* conn_list;

void*           read_thread(sock_node* node);
sock_node*      sock_node_create(x_sock* sock);
sock_node_list* sock_node_list_init();
int             sock_node_list_add(sock_node_list* list, sock_node* node);
int             sock_node_list_remove(sock_node_list* list, sock_node* node);
void*           heartbeat_thread(sock_node* node);

int main()
{
    /* 创建 x_sock 并且绑定监听 */
    x_sock* sock = x_socket();
    x_bind(sock, SERVER_IP, SERVER_PORT);
    x_listen(sock);
    /* 初始化已连接 x_sock 全局链表 */
    conn_list = sock_node_list_init();
    printf("开启服务器\n");
    /* 循环阻塞等待客户端连接 */
    while (1) {
        /* 有客户端连接 */
        x_sock*    conn_sock = x_accept(sock);
        sock_node* node      = sock_node_create(conn_sock);
        sock_node_list_add(conn_list, node);
        printf("有客户端连接  %s : %d\n", node->ip, conn_sock->remote_addr.port);
        /* 创建读取数据线程与心跳线程 */
        pthread_create(&node->recv_pt, NULL, (void*)read_thread, node);
        pthread_create(&node->heartbeat_pt, NULL, (void*)heartbeat_thread, node);
    }
}

/**
 * @brief   读取数据线程
 *
 * @param   node    已连接的 sock_node
 *
 * @return  无
 *
 * @note
 * 持续读取数据
 * 判断是否为心跳数据
 * 将所有数据转发给已连接的 x_sock
 */
void* read_thread(sock_node* node)
{
    printf("开启读取线程\n");
    char buf[1024], msg[2048];
    while (1) {
        /* 读取接收到的消息至 buf */
        memset(buf, 0, sizeof(buf));
        int len = x_read(node->sock, buf, sizeof(buf));
        if (len > 0) {
            /* 如果是心跳信息 */
            if (strcmp(buf, HEARTBEAT_MASK) == 0) {
                node->is_heartbeat_normal = 1;
                continue;
            }
            /* 如果是退出消息 */
            else if (strcmp(buf, CLOSE_MASK) == 0) {
                pthread_cancel(node->heartbeat_pt);
                printf("[%s:%d]客户端退出\n", node->ip, node->sock->remote_addr.port);
                sock_node_list_remove(conn_list, node);
                node = NULL;
                pthread_exit(NULL);
            }
            /* 将消息格式化至 msg */
            memset(msg, 0, sizeof(msg));
            sprintf(msg, "[%s:%d]:%s\n", node->ip, node->sock->remote_addr.port, buf);
            sock_node* cur = conn_list->front;
            while (cur != conn_list->back->next) {
                printf("给[%s:%d]客户端发送\n", cur->ip, cur->sock->remote_addr.port);
                x_write(cur->sock, msg, strlen(msg));
                cur = cur->next;
            }
        }
    }
}

/**
 * @brief   心跳线程
 *
 * @param   node    已连接的 sock_node
 *
 * @return  无
 *
 * @note
 * 发送心跳包,如果没有回复,则删除该 x_sock
 */
void* heartbeat_thread(sock_node* node)
{
    printf("开启心跳线程\n");
    while (1) {
        if (node != NULL) {
            x_write(node->sock, HEARTBEAT_MASK, sizeof(HEARTBEAT_MASK));
            sleep(HEARTBEAT_TIME);
            if (node->is_heartbeat_normal == -1) {
            }
            if (node->is_heartbeat_normal) {
                printf("[%s : %d] 心跳正常\n", node->ip, node->sock->remote_addr.port);
                node->is_heartbeat_normal = 0;
                continue;
            } else {
                printf("[%s : %d] 无心跳下线\n", node->ip, node->sock->remote_addr.port);
                pthread_cancel(node->recv_pt);
                sock_node_list_remove(conn_list, node);
                pthread_exit(NULL);
            }
        }
    }
}

/**
 * @brief   创建 sock_node
 *
 * @param   sock    需要保存的 x_sock
 *
 * @return  初始化的sock_node
 *
 * @note    分配内存,初始化数据,创建节点
 */
sock_node* sock_node_create(x_sock* sock)
{
    /* 分配内存 */
    sock_node* node = (sock_node*)calloc(1, sizeof(sock_node));
    /* 初始化 */
    node->sock = sock;
    struct in_addr addr;
    addr.s_addr = htonl(sock->remote_addr.ip);
    node->ip    = inet_ntoa(addr);
    return node;
}

/**
 * @brief   初始化链表
 *
 * @param   无
 *
 * @return  初始化好的 sock_node_list 链表指针
 *
 * @note    无
 */
sock_node_list* sock_node_list_init()
{
    sock_node_list* list = (sock_node_list*)calloc(1, sizeof(sock_node_list));

    list->size  = 0;
    list->front = NULL;
    list->back  = NULL;

    pthread_mutex_init(&list->lock, NULL);
    return list;
}

/**
 * @brief   往链表中添加节点
 *
 * @param   list    链表
 * @param   node    节点
 *
 * @return  链表中的节点个数
 *
 * @note    无
 */
int sock_node_list_add(sock_node_list* list, sock_node* node)
{
    /* 无效数据 */
    if (node == NULL || list == NULL) {
        return -1;
    }
    pthread_mutex_lock(&list->lock);
    /* 第一个节点 */
    if (list->size == 0) {
        list->front = list->back = node;
        list->size++;
    } else {
        node->prev       = list->back;
        list->back->next = node;
        list->back       = list->back->next;
        list->size++;
    }
    pthread_mutex_unlock(&list->lock);
    return list->size;
}

/**
 * @brief   往链表中删除节点
 *
 * @param   list    链表
 * @param   node    节点
 *
 * @return  链表中的节点个数
 *
 * @note    无
 */
int sock_node_list_remove(sock_node_list* list, sock_node* node)
{
    /* 无效数据 */
    if (node == NULL || list == NULL || list->size == 0) {
        return -1;
    }

    sock_node* cur = list->front;
    pthread_mutex_lock(&list->lock);
    while (cur != NULL) {
        if (cur == node) {
            sock_node *prev, *next;
            prev = cur->prev;
            next = cur->next;
            /* 如果是头节点 */
            if (prev == NULL) {
                list->front = next;
                if (next != NULL) {
                    list->front->prev = NULL;
                }
            }
            /* 如果是尾节点 */
            else if (next == NULL) {
                list->back       = list->back->prev;
                list->back->next = NULL;
                cur->prev        = NULL;
            }
            /* 中间节点 */
            else {
                prev->next = next;
                next->prev = prev;
            }
            pthread_cancel(cur->recv_pt);
            pthread_cancel(cur->heartbeat_pt);
            free(cur);
            // memset(cur,0,sizeof(sock_node));      //tcache_thread_shutdown(): unaligned tcache chunk detected
            cur = NULL;
            list->size--;

            pthread_mutex_unlock(&list->lock);
            return list->size;
        } else {
            cur = cur->next;
        }
    }
    pthread_mutex_unlock(&list->lock);
    return -1;
}
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "x_tcp.h"

#define CLOSE_MASK ":close"
#define HEARTBEAT_MASK "AaZzheartbeat"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1234

void *read_thread(x_tcp *sock);

int main(int argc, char *argv[])
{
    int ret;
    if (argc != 3) {
        printf("参数错误: ./client <本机IP> <端口>\n");
        return -1;
    }

    /* 判断地址 */
    char *ip   = argv[1];
    int   port = atoi(argv[2]);
    if ((strcmp(ip, SERVER_IP) == 0) && port == SERVER_PORT) {
        printf("地址与服务器冲突\n");
        return -1;
    }
    /* 创建 sock */
    x_tcp *sock = x_socket();
    /* 连接服务器 */
    if (x_connect(sock, ip, port, SERVER_IP, SERVER_PORT)) {
        printf("连接服务器错误\n");
        return -1;
    }
    printf("连接成功\n");
    pthread_t recv_pt;
    pthread_create(&recv_pt, NULL, (void *)read_thread, sock);
    char buf[1024];
    int  len;
    printf("请输入你要发送的消息:\n");
    while (1) {
        memset(buf, 0, sizeof(buf));
        scanf("%s", buf);
        if (strcmp(buf, CLOSE_MASK) == 0) {
            printf("退出连接\n");
            ret = x_write(sock, buf, strlen(buf) + 1);
            if (ret < 0) {
                printf("发送失败\n");
            } else {
                printf("发送成功\n");
            }
            x_close(sock);
            return 0;
        }
        ret = x_write(sock, buf, strlen(buf) + 1);
        if (ret < 0) {
            printf("发送失败\n");
        } else {
            printf("发送成功\n");
        }
    }
    return 0;
}

/**
 * @brief   读取数据线程
 *
 * @param   sock    已连接的 x_tcp
 *
 * @return  无
 *
 * @note
 * 持续读取数据
 * 判断是否为心跳数据
 * 将所有数据打印
 */
void *read_thread(x_tcp *sock)
{
    char buf[1024];
    int  len;
    while (1) {
        memset(buf, 0, sizeof(buf));
        len = x_read(sock, buf, sizeof(buf));
        if (len > 0) {
            if (strcmp(buf, HEARTBEAT_MASK) == 0) {
                x_write(sock, HEARTBEAT_MASK, sizeof(HEARTBEAT_MASK));
                continue;
            }
            printf("%s\n", buf);
            printf("请输入你要发送的消息:\n");
        }
    }
}
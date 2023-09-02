#ifndef _X_PACKET_H_ 
#define _X_PACKET_H_ 

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

uint16_t get_ip_tot_len(char *msg);
uint32_t get_ip_src_ip(char *msg);
uint32_t get_ip_dest_ip(char *msg);
uint16_t get_tcp_src_port(char *msg);
uint8_t  get_tcp_flags(char *msg);
uint32_t get_tcp_seq(char *msg);
uint16_t get_tcp_dest_port(char *msg);
uint32_t get_tcp_ack_seq(char *msg);
uint16_t get_tcp_windows(char *msg);
void print_packet(const char *packet);
#endif // !_X_PACKET_H_



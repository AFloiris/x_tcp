#include "x_packet.h"

uint16_t get_ip_tot_len(char *msg)
{
    int      offset = 2;
    uint16_t var;
    memcpy(&var, msg + offset, 2);
    return ntohs(var);
}

uint32_t get_ip_src_ip(char *msg)
{
    int      offset = 12;
    uint32_t var;
    memcpy(&var, msg + offset, 4);
    return ntohl(var);
}

uint32_t get_ip_dest_ip(char *msg)
{
    int      offset = 16;
    uint32_t var;
    memcpy(&var, msg + offset, 4);
    return ntohl(var);
}

uint16_t get_tcp_src_port(char *msg)
{
    int      offset = 0;
    uint16_t var;
    memcpy(&var, msg + offset, 2);
    return ntohs(var);
}

uint16_t get_tcp_dest_port(char *msg)
{
    int      offset = 2;
    uint16_t var;
    memcpy(&var, msg + offset, 2);
    return ntohs(var);
}

uint32_t get_tcp_seq(char *msg)
{
    int      offset = 4;
    uint32_t var;
    memcpy(&var, msg + offset, 4);
    return ntohl(var);
}

uint32_t get_tcp_ack_seq(char *msg)
{
    int      offset = 8;
    uint32_t var;
    memcpy(&var, msg + offset, 4);
    return ntohl(var);
}

uint8_t get_tcp_flags(char *msg)
{
    int     offset = 13;
    uint8_t var;
    memcpy(&var, msg + offset, 1);
    return var;
}
uint16_t get_tcp_windows(char *msg)
{
    int     offset = 14;
    uint16_t var;
    memcpy(&var, msg + offset, 2);
    return ntohs(var);
}

void print_packet(const char *packet)
{
    const unsigned char *ip_header = (const unsigned char *)packet;

    // IP头部
    unsigned char  ip_version             = (ip_header[0] & 0xF0) >> 4;
    unsigned char  ip_header_length       = (ip_header[0] & 0x0F) * 4;
    unsigned char  ip_tos                 = ip_header[1];
    unsigned short ip_total_length        = (ip_header[2] << 8) + ip_header[3];
    unsigned short ip_identification      = (ip_header[4] << 8) + ip_header[5];
    unsigned short ip_flags               = (ip_header[6] << 8) + ip_header[7];
    unsigned short ip_fragment_offset     = (ip_flags & 0x1FFF) * 8;
    unsigned char  ip_ttl                 = ip_header[8];
    unsigned char  ip_protocol            = ip_header[9];
    unsigned short ip_checksum            = (ip_header[10] << 8) + ip_header[11];
    unsigned int   ip_source_address      = (ip_header[12] << 24) + (ip_header[13] << 16) + (ip_header[14] << 8) + ip_header[15];
    unsigned int   ip_destination_address = (ip_header[16] << 24) + (ip_header[17] << 16) + (ip_header[18] << 8) + ip_header[19];

    printf("\n-----------------------------------------\n");
    printf("IP Header:\n");
    printf("  IP Version: %d\n", ip_version);
    printf("  IP Header Length: %d bytes\n", ip_header_length);
    printf("  Type of Service: %d\n", ip_tos);
    printf("  Total Length: %d\n", ip_total_length);
    printf("  Identification: %d\n", ip_identification);
    printf("  Flags: 0x%04X\n", ip_flags);
    printf("  Fragment Offset: %d\n", ip_fragment_offset);
    printf("  Time to Live: %d\n", ip_ttl);
    printf("  Protocol: %d\n", ip_protocol);
    printf("  Header Checksum: 0x%04X\n", ip_checksum);
    printf("  Source IP Address: %u.%u.%u.%u\n", (ip_source_address >> 24) & 0xFF, (ip_source_address >> 16) & 0xFF, (ip_source_address >> 8) & 0xFF, ip_source_address & 0xFF);
    printf("  Destination IP Address: %u.%u.%u.%u\n", (ip_destination_address >> 24) & 0xFF, (ip_destination_address >> 16) & 0xFF, (ip_destination_address >> 8) & 0xFF, ip_destination_address & 0xFF);
    printf("\n-----------------------------------------\n");

    // TCP头部
    const unsigned char *tcp_header                = ip_header + ip_header_length;

    unsigned short       tcp_source_port           = (tcp_header[0] << 8) + tcp_header[1];
    unsigned short       tcp_destination_port      = (tcp_header[2] << 8) + tcp_header[3];
    unsigned int         tcp_sequence_number       = (tcp_header[4] << 24) + (tcp_header[5] << 16) + (tcp_header[6] << 8) + tcp_header[7];
    unsigned int         tcp_acknowledgment_number = (tcp_header[8] << 24) + (tcp_header[9] << 16) + (tcp_header[10] << 8) + tcp_header[11];
    unsigned char        tcp_offset                = (tcp_header[12] & 0xF0) >> 4;
    unsigned char        tcp_flags                 = tcp_header[13];
    unsigned short       tcp_window                = (tcp_header[14] << 8) + tcp_header[15];
    unsigned short       tcp_checksum              = (tcp_header[16] << 8) + tcp_header[17];
    unsigned short       tcp_urgent_pointer        = (tcp_header[18] << 8) + tcp_header[19];
    printf("\n-----------------------------------------\n");
    printf("TCP Header:\n");
    printf("  Source Port: %d\n", tcp_source_port);
    printf("  Destination Port: %d\n", tcp_destination_port);
    printf("  Sequence Number: %u\n", tcp_sequence_number);
    printf("  Acknowledgment Number: %u\n", tcp_acknowledgment_number);
    printf("  TCP Header Length: %d bytes\n", tcp_offset * 4);
    printf("  Flags: 0x%02X\n", tcp_flags);
    printf("  Window Size: %d\n", tcp_window);
    printf("  Checksum: 0x%04X\n", tcp_checksum);
    printf("  Urgent Pointer: %d\n", tcp_urgent_pointer);
    printf("\n-----------------------------------------\n");
}

#include <netinet/in.h>

typedef struct {
    uint8_t version_and_ihl;
    uint8_t dscp_and_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sip_;
    uint32_t dip_;
} IpHdr;

typedef struct{
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;
    u_int8_t th_off:4;
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;
    u_int8_t th_x2:4;
#  endif
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH        0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
} TcpHdr;
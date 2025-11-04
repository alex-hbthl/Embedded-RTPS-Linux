#ifndef RTPS_IPTYPES_H
#define RTPS_IPTYPES_H

#include <cstdint>

#ifndef EMBRTPS_USE_SOCKETS
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip_addr.h"
using ip4_struct_t = ip4_addr_t;
using ip_struct_t = ip_addr_t;
#else
#include <netinet/in.h>

struct ip4_struct{
  in_addr_t addr;
};
typedef struct ip4_struct ip4_struct_t;

struct ip6_struct {
  uint32_t addr[4];
  uint8_t zone;
};
typedef struct ip6_struct ip6_struct_t;

// from lwip
enum ip_addr_type_enum : uint8_t {
  /** IPv4 */
  IPADDR_TYPE_V4 =   0U,
  /** IPv6 */
  IPADDR_TYPE_V6 =   6U,
  /** IPv4+IPv6 ("dual-stack") */
  IPADDR_TYPE_ANY = 46U
};

typedef struct ip_struct {
  union {
    ip6_struct_t ip6;
    ip4_struct_t ip4;
  } u_addr;
  ip_addr_type_enum type;
} ip_struct_t;

#endif

#endif // RTPS_IPTYPES_H

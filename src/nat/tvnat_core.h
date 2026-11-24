/*
 * tvnat_core.h — pure packet/NAT logic for the TechVision gateway NAT
 * helper. No Windows headers, no WinDivert: this file compiles and is
 * unit-tested natively on Linux (see test/test_core.c), and is also
 * compiled into the Windows helper tvnat.exe (see tvnat.c).
 *
 * Model (one gateway PC per site; see src/nat-gateway.js and the spec):
 *   - Same-subnet pair: a remote device 192.168.1.3 is addressed on
 *     this LAN as a VIRTUAL address 192.168.1.203 (1:1 mapping).
 *     The gateway answers ARP for the virtual address (secondary IP
 *     on its LAN interface) and translates.
 *   - Different-subnet pair: no address translation at all — the
 *     remote subnet is real and routable; the helper only forwards.
 *
 * A flow stores the same conversation twice: once as the LAN sees it
 * (lan_*) and once as the tunnel sees it (tun_*). A packet arriving
 * in either address space is matched forward or reverse against the
 * stored tuples and rewritten to the other space. That one rule
 * covers all four legs:
 *   LAN  origSrc -> virtDst   => tunnel gwTunnel -> realDst
 *   tun  realDst -> gwTunnel  => LAN   virtDst -> origSrc   (reply)
 *   tun  remoteTunnel -> localReal => LAN farVirt -> localReal
 *   LAN  localReal -> farVirt => tunnel localReal -> remoteTunnel (reply)
 * Flows expire (TCP 600 s, UDP 120 s, ICMP/other 60 s). A reply with
 * no live flow is DROPPED (return -1), never passed through
 * untranslated — an untranslated reply would leak a real address
 * into the wrong subnet and break the collision hiding.
 */
#ifndef TVNAT_CORE_H
#define TVNAT_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TVNAT_MAX_MAPPINGS 256
#define TVNAT_MAX_FLOWS 4096
#define TVNAT_SNAT_PORT_MIN 40000
#define TVNAT_SNAT_PORT_MAX 60999

#define TVNAT_TIMEOUT_TCP_MS   (600 * 1000)
#define TVNAT_TIMEOUT_UDP_MS   (120 * 1000)
#define TVNAT_TIMEOUT_OTHER_MS (60 * 1000)

/* One 1:1 mapping. IPs are uint32 in NETWORK byte order, i.e. the
 * value as it appears on the wire: 192.168.1.3 == 0xC0A80103. */
typedef struct {
    uint32_t real;              /* remote device's real address */
    uint32_t virt;              /* virtual address on this LAN */
    char name[64];
} tvnat_mapping_t;

typedef struct {
    tvnat_mapping_t items[TVNAT_MAX_MAPPINGS];
    int count;
} tvnat_map_t;

/* 0 = ok, -1 = duplicate real/virtual or table full. */
int tvnat_map_add(tvnat_map_t *map, uint32_t real, uint32_t virt,
                  const char *name);
const tvnat_mapping_t *tvnat_map_by_real(const tvnat_map_t *map,
                                         uint32_t real);
const tvnat_mapping_t *tvnat_map_by_virt(const tvnat_map_t *map,
                                         uint32_t virt);

/* --- IP helpers (network byte order throughout) --- */
/* Parse "a.b.c.d". Returns 0 on invalid input (0.0.0.0 is never a
 * valid mapping address, so 0 doubles as the error value). */
uint32_t tvnat_ip_parse(const char *s);
void tvnat_ip_format(uint32_t ip, char *out, size_t out_len);
/* "192.168.1.0/24" -> network + prefix. Returns 0 on success. */
int tvnat_cidr_parse(const char *s, uint32_t *network, int *prefix);
int tvnat_in_subnet(uint32_t ip, uint32_t network, int prefix);
uint32_t tvnat_subnet_mask(int prefix);

/* --- checksums (all verified against known vectors in test_core.c) --- */
/* Raw ones-complement sum over bytes (odd length padded with zero). */
uint16_t tvnat_checksum(const uint8_t *data, size_t len);
/* IPv4 header checksum (header bytes with the checksum field zeroed). */
uint16_t tvnat_ipv4_checksum(const uint8_t *ip_hdr, size_t hdr_len);
/* TCP/UDP checksum including the IPv4 pseudo-header. */
uint16_t tvnat_l4_checksum(uint32_t src, uint32_t dst, uint8_t proto,
                           const uint8_t *seg, size_t seg_len);
/* ICMP checksum (no pseudo-header). */
uint16_t tvnat_icmp_checksum(const uint8_t *seg, size_t seg_len);
/* Recompute the IPv4 header checksum and the TCP/UDP/ICMP checksum
 * of a whole packet in place. Returns 0, or -1 if the packet is not
 * a parseable IPv4 packet. Fragmented packets (MF set or offset != 0)
 * get only the IPv4 header checksum: their L4 header may not be in
 * this fragment, so touching it would corrupt the packet. */
int tvnat_fix_checksums(uint8_t *pkt, size_t len);

/* --- packet field access (network byte order) --- */
int tvnat_packet_fields(const uint8_t *pkt, size_t len, uint8_t *proto,
                        uint32_t *src, uint32_t *dst, uint16_t *sport,
                        uint16_t *dport);
/* Rewrite src/dst (and sport/dport for TCP/UDP, ICMP id for ICMP)
 * in place, then fix the checksums. Returns 0 or -1. */
int tvnat_packet_rewrite(uint8_t *pkt, size_t len, uint32_t src,
                         uint32_t dst, uint16_t sport, uint16_t dport);

/* --- flows --- */
typedef struct {
    uint8_t proto;
    uint32_t lan_src, lan_dst, tun_src, tun_dst;
    uint16_t lan_sport, lan_dport, tun_sport, tun_dport;
    uint64_t last_seen_ms;
} tvnat_flow_t;

typedef struct {
    tvnat_flow_t items[TVNAT_MAX_FLOWS];
    int count;
} tvnat_flows_t;

typedef struct {
    uint32_t gw_tunnel_ip;      /* this gateway's 10.0.0.x */
    uint32_t remote_tunnel_ip;  /* the other gateway's 10.0.0.y */
    uint32_t far_virt_ip;       /* virtual address that stands for the
                                   remote gateway on this LAN (same-
                                   subnet mode); 0 in different-subnet
                                   mode where it is not used */
    const tvnat_map_t *map;     /* 1:1 mappings (same-subnet mode) */
} tvnat_cfg_t;

/*
 * Translate one packet in place.
 *   from_tunnel = 0: packet arrived from the LAN side.
 *   from_tunnel = 1: packet arrived from the tunnel side.
 * Returns 1 = translated (checksums fixed), 0 = not NAT traffic,
 * pass through unchanged, -1 = drop (reply with no live flow, or a
 * malformed packet). `now_ms` is a millisecond clock for expiry.
 */
int tvnat_translate(uint8_t *pkt, size_t len, int from_tunnel,
                    const tvnat_cfg_t *cfg, tvnat_flows_t *flows,
                    uint64_t now_ms);

/* Test/observation helpers. */
int tvnat_flow_count(const tvnat_flows_t *flows);
uint64_t tvnat_flow_timeout_ms(uint8_t proto);

#ifdef __cplusplus
}
#endif
#endif /* TVNAT_CORE_H */

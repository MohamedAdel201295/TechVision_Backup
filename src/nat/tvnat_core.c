/*
 * tvnat_core.c — pure NAT logic. See tvnat_core.h for the model.
 * No OS calls except for nothing at all: this file is deliberately
 * portable C99 so the same code is tested on Linux and shipped on
 * Windows.
 */
#include "tvnat_core.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* mappings                                                           */
/* ------------------------------------------------------------------ */

int tvnat_map_add(tvnat_map_t *map, uint32_t real, uint32_t virt,
                  const char *name) {
    int i;
    if (!map || !real || !virt || real == virt) return -1;
    if (map->count >= TVNAT_MAX_MAPPINGS) return -1;
    for (i = 0; i < map->count; i++) {
        if (map->items[i].real == real || map->items[i].virt == virt)
            return -1;
    }
    map->items[map->count].real = real;
    map->items[map->count].virt = virt;
    if (name) {
        size_t n = strlen(name);
        if (n > sizeof(map->items[map->count].name) - 1)
            n = sizeof(map->items[map->count].name) - 1;
        memcpy(map->items[map->count].name, name, n);
        map->items[map->count].name[n] = '\0';
    } else {
        map->items[map->count].name[0] = '\0';
    }
    map->count++;
    return 0;
}

const tvnat_mapping_t *tvnat_map_by_real(const tvnat_map_t *map,
                                         uint32_t real) {
    int i;
    if (!map) return NULL;
    for (i = 0; i < map->count; i++)
        if (map->items[i].real == real) return &map->items[i];
    return NULL;
}

const tvnat_mapping_t *tvnat_map_by_virt(const tvnat_map_t *map,
                                         uint32_t virt) {
    int i;
    if (!map) return NULL;
    for (i = 0; i < map->count; i++)
        if (map->items[i].virt == virt) return &map->items[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* IP helpers                                                         */
/* ------------------------------------------------------------------ */

uint32_t tvnat_ip_parse(const char *s) {
    unsigned a, b, c, d;
    char extra;
    if (!s) return 0;
    /* %c at the end rejects trailing junk like "1.2.3.4x". */
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c << 8) | (uint32_t)d;
}

void tvnat_ip_format(uint32_t ip, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    snprintf(out, out_len, "%u.%u.%u.%u",
             (unsigned)((ip >> 24) & 0xFF),
             (unsigned)((ip >> 16) & 0xFF),
             (unsigned)((ip >> 8) & 0xFF), (unsigned)(ip & 0xFF));
}

uint32_t tvnat_subnet_mask(int prefix) {
    if (prefix <= 0) return 0;
    if (prefix >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - prefix);
}

int tvnat_cidr_parse(const char *s, uint32_t *network, int *prefix) {
    char addr[64];
    const char *slash;
    size_t n;
    int p;
    char extra;
    if (!s || !network || !prefix) return -1;
    slash = strchr(s, '/');
    if (!slash) return -1;
    n = (size_t)(slash - s);
    if (n == 0 || n >= sizeof(addr)) return -1;
    memcpy(addr, s, n);
    addr[n] = '\0';
    if (sscanf(slash + 1, "%d%c", &p, &extra) != 1) return -1;
    if (p < 0 || p > 32) return -1;
    *network = tvnat_ip_parse(addr);
    if (!*network && strcmp(addr, "0.0.0.0") != 0) return -1;
    *network &= tvnat_subnet_mask(p);
    *prefix = p;
    return 0;
}

int tvnat_in_subnet(uint32_t ip, uint32_t network, int prefix) {
    uint32_t mask = tvnat_subnet_mask(prefix);
    return (ip & mask) == (network & mask);
}

/* ------------------------------------------------------------------ */
/* checksums                                                          */
/* ------------------------------------------------------------------ */

uint16_t tvnat_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < len; i += 2)
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    if (len & 1) sum += ((uint32_t)data[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

uint16_t tvnat_ipv4_checksum(const uint8_t *ip_hdr, size_t hdr_len) {
    return tvnat_checksum(ip_hdr, hdr_len);
}

uint16_t tvnat_l4_checksum(uint32_t src, uint32_t dst, uint8_t proto,
                           const uint8_t *seg, size_t seg_len) {
    /* Pseudo-header (12 bytes) + segment. Build the sum without
     * allocating: sum the pseudo-header words, then the segment. */
    uint32_t sum = 0;
    size_t i;
    sum += (src >> 16) & 0xFFFF;
    sum += src & 0xFFFF;
    sum += (dst >> 16) & 0xFFFF;
    sum += dst & 0xFFFF;
    sum += (uint32_t)proto; /* zero byte + protocol */
    sum += (uint32_t)seg_len;
    for (i = 0; i + 1 < seg_len; i += 2)
        sum += ((uint32_t)seg[i] << 8) | seg[i + 1];
    if (seg_len & 1) sum += ((uint32_t)seg[seg_len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

uint16_t tvnat_icmp_checksum(const uint8_t *seg, size_t seg_len) {
    return tvnat_checksum(seg, seg_len);
}

/* ------------------------------------------------------------------ */
/* packet field access                                                */
/* ------------------------------------------------------------------ */

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

/* Returns 1 if this is a fragment that is not the first (or MF set
 * with a non-zero offset): the L4 header is not guaranteed present. */
static int is_fragment(const uint8_t *ip, size_t ip_len) {
    uint16_t frag;
    (void)ip_len;
    frag = rd16(ip + 6);
    return (frag & 0x1FFF) != 0 || (frag & 0x2000) != 0;
}

int tvnat_packet_fields(const uint8_t *pkt, size_t len, uint8_t *proto,
                        uint32_t *src, uint32_t *dst, uint16_t *sport,
                        uint16_t *dport) {
    size_t ihl;
    const uint8_t *l4;
    if (!pkt || len < 20) return -1;
    if ((pkt[0] >> 4) != 4) return -1; /* IPv4 only */
    ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl) return -1;
    if (proto) *proto = pkt[9];
    if (src) *src = rd32(pkt + 12);
    if (dst) *dst = rd32(pkt + 16);
    if (sport) *sport = 0;
    if (dport) *dport = 0;
    if (is_fragment(pkt, ihl)) return 0; /* no L4 fields in fragment */
    l4 = pkt + ihl;
    if (pkt[9] == 6 || pkt[9] == 17) { /* TCP / UDP */
        if (len < ihl + 4) return -1;
        if (sport) *sport = rd16(l4);
        if (dport) *dport = rd16(l4 + 2);
    } else if (pkt[9] == 1) { /* ICMP: identifier is the "port" */
        if (len < ihl + 6) return -1;
        if (sport) *sport = rd16(l4 + 4);
        if (dport) *dport = rd16(l4 + 4);
    }
    return 0;
}

int tvnat_fix_checksums(uint8_t *pkt, size_t len) {
    size_t ihl, total;
    uint8_t proto;
    if (!pkt || len < 20) return -1;
    if ((pkt[0] >> 4) != 4) return -1;
    ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl) return -1;
    total = rd16(pkt + 2);
    if (total == 0 || total > len) total = len; /* tolerate short reads */
    if (total < ihl) return -1;
    proto = pkt[9];
    /* IPv4 header checksum. */
    wr16(pkt + 10, 0);
    wr16(pkt + 10, tvnat_ipv4_checksum(pkt, ihl));
    if (is_fragment(pkt, ihl)) return 0;
    if (proto == 6 || proto == 17) {
        uint8_t *seg = pkt + ihl;
        size_t seg_len = total - ihl;
        uint32_t src = rd32(pkt + 12), dst = rd32(pkt + 16);
        size_t csum_off = (proto == 6) ? 16 : 6;
        if (seg_len < csum_off + 2) return -1;
        wr16(seg + csum_off, 0);
        /* UDP checksum of 0 means "not computed" (RFC 768) — but a
         * NAT that rewrites addresses MUST recompute it, otherwise
         * the receiver drops the packet. A computed value of 0 is
         * transmitted as 0xFFFF. */
        {
            uint16_t c = tvnat_l4_checksum(src, dst, proto, seg, seg_len);
            if (proto == 17 && c == 0) c = 0xFFFF;
            wr16(seg + csum_off, c);
        }
    } else if (proto == 1) {
        uint8_t *seg = pkt + ihl;
        size_t seg_len = total - ihl;
        if (seg_len < 4) return -1;
        wr16(seg + 2, 0);
        wr16(seg + 2, tvnat_icmp_checksum(seg, seg_len));
    }
    return 0;
}

int tvnat_packet_rewrite(uint8_t *pkt, size_t len, uint32_t src,
                         uint32_t dst, uint16_t sport, uint16_t dport) {
    size_t ihl;
    uint8_t proto;
    if (!pkt || len < 20) return -1;
    if ((pkt[0] >> 4) != 4) return -1;
    ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl) return -1;
    proto = pkt[9];
    wr32(pkt + 12, src);
    wr32(pkt + 16, dst);
    if (!is_fragment(pkt, ihl)) {
        uint8_t *l4 = pkt + ihl;
        if (proto == 6 || proto == 17) {
            if (len < ihl + 4) return -1;
            wr16(l4, sport);
            wr16(l4 + 2, dport);
        } else if (proto == 1) {
            if (len < ihl + 6) return -1;
            wr16(l4 + 4, sport); /* ICMP identifier */
        }
    }
    return tvnat_fix_checksums(pkt, len);
}

/* ------------------------------------------------------------------ */
/* flows                                                              */
/* ------------------------------------------------------------------ */

uint64_t tvnat_flow_timeout_ms(uint8_t proto) {
    if (proto == 6) return TVNAT_TIMEOUT_TCP_MS;
    if (proto == 17) return TVNAT_TIMEOUT_UDP_MS;
    return TVNAT_TIMEOUT_OTHER_MS;
}

int tvnat_flow_count(const tvnat_flows_t *flows) {
    return flows ? flows->count : 0;
}

static int flow_expired(const tvnat_flow_t *f, uint64_t now_ms) {
    return now_ms >= f->last_seen_ms &&
           (now_ms - f->last_seen_ms) > tvnat_flow_timeout_ms(f->proto);
}

/* Remove expired flows in place. */
static void flow_sweep(tvnat_flows_t *flows, uint64_t now_ms) {
    int i, w = 0;
    if (!flows) return;
    for (i = 0; i < flows->count; i++) {
        if (!flow_expired(&flows->items[i], now_ms)) {
            if (w != i) flows->items[w] = flows->items[i];
            w++;
        }
    }
    flows->count = w;
}

/* Does this flow's TUN tuple (in the given direction) already use
 * (src, sport, dst, dport)? Used to avoid SNAT port collisions. */
static int tun_tuple_used(const tvnat_flows_t *flows, uint8_t proto,
                          uint32_t src, uint16_t sport, uint32_t dst,
                          uint16_t dport, uint64_t now_ms) {
    int i;
    for (i = 0; i < flows->count; i++) {
        const tvnat_flow_t *f = &flows->items[i];
        if (flow_expired(f, now_ms)) continue;
        if (f->proto != proto) continue;
        if ((f->tun_src == src && f->tun_sport == sport &&
             f->tun_dst == dst && f->tun_dport == dport) ||
            (f->tun_dst == src && f->tun_dport == sport &&
             f->tun_src == dst && f->tun_sport == dport))
            return 1;
    }
    return 0;
}

static uint16_t alloc_snat_port(tvnat_flows_t *flows, uint8_t proto,
                                uint32_t gw_ip, uint16_t want,
                                uint32_t dst, uint16_t dport,
                                uint64_t now_ms) {
    uint16_t p;
    if (!tun_tuple_used(flows, proto, gw_ip, want, dst, dport, now_ms))
        return want;
    for (p = TVNAT_SNAT_PORT_MIN; p <= TVNAT_SNAT_PORT_MAX; p++) {
        if (!tun_tuple_used(flows, proto, gw_ip, p, dst, dport, now_ms))
            return p;
    }
    return 0; /* no free port */
}

/* Match a packet tuple against a flow in one address space.
 * Returns 1 = forward match, -1 = reverse match, 0 = no match. */
static int flow_match(const tvnat_flow_t *f, int in_tun_space,
                      uint8_t proto, uint32_t src, uint16_t sport,
                      uint32_t dst, uint16_t dport) {
    uint32_t fsrc, fdst;
    uint16_t fsport, fdport;
    if (f->proto != proto) return 0;
    if (in_tun_space) {
        fsrc = f->tun_src; fsport = f->tun_sport;
        fdst = f->tun_dst; fdport = f->tun_dport;
    } else {
        fsrc = f->lan_src; fsport = f->lan_sport;
        fdst = f->lan_dst; fdport = f->lan_dport;
    }
    if (src == fsrc && sport == fsport && dst == fdst && dport == fdport)
        return 1;
    if (src == fdst && sport == fdport && dst == fsrc && dport == fsport)
        return -1;
    return 0;
}

static int flow_insert(tvnat_flows_t *flows, const tvnat_flow_t *f,
                       uint64_t now_ms) {
    flow_sweep(flows, now_ms);
    if (flows->count >= TVNAT_MAX_FLOWS) return -1;
    flows->items[flows->count] = *f;
    flows->items[flows->count].last_seen_ms = now_ms;
    flows->count++;
    return 0;
}

int tvnat_translate(uint8_t *pkt, size_t len, int from_tunnel,
                    const tvnat_cfg_t *cfg, tvnat_flows_t *flows,
                    uint64_t now_ms) {
    uint8_t proto;
    uint32_t src, dst;
    uint16_t sport, dport;
    int i, m;
    if (!pkt || !cfg || !flows) return -1;
    if (tvnat_packet_fields(pkt, len, &proto, &src, &dst, &sport,
                            &dport) != 0)
        return -1;

    /* 1. Existing flow? Match in the space the packet is in now. */
    for (i = 0; i < flows->count; i++) {
        tvnat_flow_t *f = &flows->items[i];
        if (flow_expired(f, now_ms)) continue;
        m = flow_match(f, from_tunnel, proto, src, sport, dst, dport);
        if (m == 1) {
            /* Forward: rewrite to the other space, same direction. */
            uint32_t ns, nd;
            uint16_t nsp, ndp;
            if (from_tunnel) {
                ns = f->lan_src; nsp = f->lan_sport;
                nd = f->lan_dst; ndp = f->lan_dport;
            } else {
                ns = f->tun_src; nsp = f->tun_sport;
                nd = f->tun_dst; ndp = f->tun_dport;
            }
            f->last_seen_ms = now_ms;
            return tvnat_packet_rewrite(pkt, len, ns, nd, nsp, ndp) == 0
                       ? 1
                       : -1;
        }
        if (m == -1) {
            /* Reverse: rewrite to the other space, swapped. */
            uint32_t ns, nd;
            uint16_t nsp, ndp;
            if (from_tunnel) {
                ns = f->lan_dst; nsp = f->lan_dport;
                nd = f->lan_src; ndp = f->lan_sport;
            } else {
                ns = f->tun_dst; nsp = f->tun_dport;
                nd = f->tun_src; ndp = f->tun_sport;
            }
            f->last_seen_ms = now_ms;
            return tvnat_packet_rewrite(pkt, len, ns, nd, nsp, ndp) == 0
                       ? 1
                       : -1;
        }
    }

    /* 2. No flow yet: only an initiating packet may create one. */
    if (!from_tunnel) {
        /* LAN -> virtual address: start an outbound flow. */
        const tvnat_mapping_t *map = NULL;
        tvnat_flow_t f;
        uint16_t mapped_sport;
        if (cfg->map) map = tvnat_map_by_virt(cfg->map, dst);
        if (map) {
            if (!cfg->gw_tunnel_ip) return 0;
            mapped_sport = alloc_snat_port(flows, proto,
                                           cfg->gw_tunnel_ip, sport,
                                           map->real, dport, now_ms);
            if (mapped_sport == 0) return -1; /* SNAT ports exhausted */
            memset(&f, 0, sizeof(f));
            f.proto = proto;
            f.lan_src = src; f.lan_sport = sport;
            f.lan_dst = dst; f.lan_dport = dport;
            f.tun_src = cfg->gw_tunnel_ip; f.tun_sport = mapped_sport;
            f.tun_dst = map->real; f.tun_dport = dport;
            if (flow_insert(flows, &f, now_ms) != 0) return -1;
            return tvnat_packet_rewrite(pkt, len, f.tun_src, f.tun_dst,
                                        f.tun_sport,
                                        f.tun_dport) == 0
                       ? 1
                       : -1;
        }
        /* LAN -> far gateway's virtual address: this is the reply
         * leg of an inbound-initiated flow, which would have matched
         * in step 1. No flow => unsolicited => drop. */
        if (cfg->far_virt_ip && dst == cfg->far_virt_ip) return -1;
        return 0;
    } else {
        /* Tunnel -> this LAN, sent by the remote gateway: start an
         * inbound flow (src becomes the far gateway's virtual IP so
         * the local device replies to an address on its own subnet,
         * i.e. back through this gateway). */
        tvnat_flow_t f;
        if (!cfg->remote_tunnel_ip || src != cfg->remote_tunnel_ip)
            return 0; /* not from the remote gateway: not our traffic */
        if (!cfg->far_virt_ip) return 0; /* different-subnet mode:
            no translation needed, pass through */
        memset(&f, 0, sizeof(f));
        f.proto = proto;
        f.tun_src = src; f.tun_sport = sport;
        f.tun_dst = dst; f.tun_dport = dport;
        f.lan_src = cfg->far_virt_ip; f.lan_sport = sport;
        f.lan_dst = dst; f.lan_dport = dport;
        if (flow_insert(flows, &f, now_ms) != 0) return -1;
        return tvnat_packet_rewrite(pkt, len, f.lan_src, f.lan_dst,
                                    f.lan_sport, f.lan_dport) == 0
                   ? 1
                   : -1;
    }
}

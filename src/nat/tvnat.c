/*
 * tvnat.c — the native half of the TechVision gateway NAT service.
 *
 * A thin main() around tvnat_core.c (pure, portable NAT logic) plus
 * WinDivert 2.2.2 (official signed binaries, bundled unmodified in
 * vendor/ — this file only LINKS the import library, it does not
 * modify the driver or the DLL).
 *
 * What it does, once per packet:
 *   1. WinDivertRecv on the NETWORK layer with a narrow filter (only
 *      the NAT scheme's own addresses — built by Node, see
 *      src/nat-gateway.js buildFilter()).
 *   2. Decide which side the packet came from by its ADDRESSES
 *      (src == remote gateway's tunnel IP, or dst == this gateway's
 *      tunnel IP, means it arrived through the tunnel; anything else
 *      matched the filter because it is addressed to a virtual
 *      address, so it came from the LAN). The interface index is
 *      NOT used for the decision: a LAN device could, in principle,
 *      address the tunnel IP directly, and the core still passes
 *      such a packet through untranslated (see below).
 *   3. tvnat_translate() rewrites it in place (or says pass/drop).
 *   4. Translated packets are re-injected with WinDivertSend:
 *      - LAN -> tunnel: the rewritten destination is the remote
 *        device's REAL address, which collides with this LAN's own
 *        subnet — the local routing table would send it back out
 *        the LAN interface to the WRONG (local) device. So the
 *        packet is steered out the tunnel interface instead:
 *        Outbound = 1, IfIdx = the Wintun interface that owns this
 *        gateway's tunnel address (resolved at startup with
 *        GetAdaptersAddresses). The tunnel service then encrypts it
 *        per its peer AllowedIPs. NOTE: those AllowedIPs must cover
 *        the remote real addresses, or the tunnel service drops the
 *        packet — that is a WireGuard config point, not something
 *        this helper can fix (see the report / spec note).
 *      - Tunnel -> LAN: re-injected unchanged (inbound, same
 *        address struct) — the stack forwards it out the LAN
 *        interface, since its destination is a real local address.
 *      - Pass-through (core returned 0, e.g. a local device pinging
 *        the gateway's tunnel IP): re-injected byte-identical.
 *      - Drop (core returned -1, e.g. a reply with no live flow):
 *        simply never sent — an untranslated reply would leak a
 *        real address into the wrong subnet.
 *   5. Checksums are recomputed by tvnat_core itself on every
 *      rewrite, and once more here with
 *      WinDivertHelperCalcChecksums() — the WinDivert helper is the
 *      authority, so a packet never leaves with a stale checksum.
 *
 * Input/output protocol (stdin/stdout, one JSON object per line —
 * the Node side is src/nat-gateway.js):
 *   stdin:  {"type":"config", "gwTunnelIp":"10.0.0.1",
 *            "remoteTunnelIp":"10.0.0.2", "farVirtIp":"192.168.1.201",
 *            "filter":"...", "mappings":[{"real":"192.168.1.3",
 *            "virt":"192.168.1.203","name":"printer"}, ...]}
 *   stdout: {"type":"ready","filter":"...","mappings":N}
 *           {"type":"log","level":"info"|"error","msg":"..."}
 *           {"type":"stats","packets":N,"translated":N,"passed":N,
 *            "dropped":N}              (about every 5 s)
 *           {"type":"error","msg":"..."} (fatal, exits non-zero)
 *   stdin:  {"type":"stop"} — or EOF on stdin — shuts the WinDivert
 *           handle down and exits 0.
 *
 * Modes:
 *   tvnat.exe                 read the config line from stdin, run.
 *   tvnat.exe --config-file <path>   read it from a file instead.
 *   tvnat.exe --check         read the config, validate it and the
 *           filter with WinDivertHelperCompileFilter (no driver
 *           needed, no handle opened), print {"type":"ready",...}
 *           and exit 0. This is the no-driver smoke test.
 *   tvnat.exe --version       print the version line, exit 0.
 *
 * This helper CANNOT run in the Linux sandbox (it is a Windows
 * .exe that opens a kernel driver). It is cross-compiled here with
 * mingw (see Makefile) and its behaviour on a real LAN — driver
 * load, packet translation, throughput, proxy ARP via the secondary
 * IPs Node adds — is Windows-only, provable only on the user's
 * machine.
 */
#define _WIN32_WINNT 0x0600
/* winsock2.h (and ws2tcpip.h) MUST come before windows.h /
 * iphlpapi.h, or PIP_ADAPTER_ADDRESSES and friends are undeclared. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tvnat_core.h"
#include "windivert.h"

#define TVNAT_VERSION "1.0.0 (WinDivert 2.2.2)"
#define TVNAT_MAX_PACKET 65535
#define TVNAT_STATS_MS 5000

static volatile LONG g_stop = 0;
static HANDLE g_handle = INVALID_HANDLE_VALUE;

/* ------------------------------------------------------------------ */
/* tiny JSON extraction (no JSON library on Windows here)             */
/* ------------------------------------------------------------------ */

/* Copy the string value of "key" (first occurrence) into out.
 * Returns 0 on success, -1 when the key is absent or malformed.
 * Handles \" escapes only (the config writer never emits others). */
static int json_get_string(const char *json, const char *key,
                           char *out, size_t out_len) {
    char pat[96];
    const char *p, *v, *e;
    size_t n;
    if (!json || !key || !out || out_len == 0) return -1;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    v = p + 1;
    e = v;
    n = 0;
    while (*e && *e != '"') {
        if (*e == '\\' && e[1]) e += 2;
        else e++;
    }
    if (*e != '"') return -1;
    /* Unescape \" and \\ while copying. */
    while (v < e && n + 1 < out_len) {
        if (*v == '\\' && v + 1 < e && (v[1] == '"' || v[1] == '\\')) {
            out[n++] = v[1];
            v += 2;
        } else {
            out[n++] = *v++;
        }
    }
    out[n] = '\0';
    return 0;
}

/* Parse the "mappings" array: for each {"real":...,"virt":...}
 * object, add it to the map. Returns 0, or -1 with *err set to a
 * short reason. `name` is display-only and ignored here. */
static int parse_mappings(const char *json, tvnat_map_t *map,
                          char *err, size_t err_len) {
    const char *p;
    int count = 0;
    if (!json || !map) return -1;
    p = strstr(json, "\"mappings\"");
    if (!p) {
        snprintf(err, err_len, "config has no \"mappings\" array");
        return -1;
    }
    p = strchr(p, '[');
    if (!p) {
        snprintf(err, err_len, "config \"mappings\" is not an array");
        return -1;
    }
    p++;
    for (;;) {
        char real_s[64], virt_s[64];
        uint32_t real, virt;
        const char *obj;
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' ||
               *p == ',')
            p++;
        if (*p == ']') break;
        if (*p != '{') {
            snprintf(err, err_len, "mapping %d is not an object",
                     count + 1);
            return -1;
        }
        obj = p;
        /* Find the end of this object (no nested objects inside). */
        p = strchr(p, '}');
        if (!p) {
            snprintf(err, err_len, "mapping %d is unterminated",
                     count + 1);
            return -1;
        }
        {
            /* Copy just this object out so json_get_string cannot
             * wander into the NEXT mapping's fields. */
            char buf[512];
            size_t n = (size_t)(p - obj) + 1;
            if (n >= sizeof(buf)) n = sizeof(buf) - 1;
            memcpy(buf, obj, n);
            buf[n] = '\0';
            if (json_get_string(buf, "real", real_s, sizeof(real_s)) != 0 ||
                json_get_string(buf, "virt", virt_s, sizeof(virt_s)) != 0) {
                snprintf(err, err_len,
                         "mapping %d needs \"real\" and \"virt\"",
                         count + 1);
                return -1;
            }
        }
        p++; /* past '}' */
        real = tvnat_ip_parse(real_s);
        virt = tvnat_ip_parse(virt_s);
        if (!real || !virt) {
            snprintf(err, err_len,
                     "mapping %d has an invalid address (%s -> %s)",
                     count + 1, real_s, virt_s);
            return -1;
        }
        if (tvnat_map_add(map, real, virt, NULL) != 0) {
            snprintf(err, err_len,
                     "mapping %d duplicates an address or the table "
                     "is full (%s -> %s)",
                     count + 1, real_s, virt_s);
            return -1;
        }
        count++;
    }
    if (count == 0) {
        snprintf(err, err_len, "config has no mappings");
        return -1;
    }
    return 0;
}

typedef struct {
    tvnat_cfg_t cfg;
    tvnat_map_t map;
    char filter[8192];
    uint32_t tunnel_ifidx; /* 0 = unknown: no steering, log a warning */
} tvnat_run_cfg_t;

/* Read the config line and fill run_cfg. Returns 0, or -1 with *err
 * set. `filter` comes from Node (built by buildFilter()); when it is
 * absent we rebuild it from the mappings — same rule, so a stale
 * Node and a new helper still agree. */
static int parse_config(const char *json, tvnat_run_cfg_t *run,
                        char *err, size_t err_len) {
    char gw_s[64], rem_s[64], far_s[64];
    memset(run, 0, sizeof(*run));
    if (json_get_string(json, "gwTunnelIp", gw_s, sizeof(gw_s)) != 0 ||
        json_get_string(json, "remoteTunnelIp", rem_s, sizeof(rem_s)) != 0 ||
        json_get_string(json, "farVirtIp", far_s, sizeof(far_s)) != 0) {
        snprintf(err, err_len,
                 "config needs gwTunnelIp, remoteTunnelIp and "
                 "farVirtIp");
        return -1;
    }
    run->cfg.gw_tunnel_ip = tvnat_ip_parse(gw_s);
    run->cfg.remote_tunnel_ip = tvnat_ip_parse(rem_s);
    run->cfg.far_virt_ip = tvnat_ip_parse(far_s);
    if (!run->cfg.gw_tunnel_ip || !run->cfg.remote_tunnel_ip ||
        !run->cfg.far_virt_ip) {
        snprintf(err, err_len,
                 "config has an invalid tunnel/virtual address "
                 "(%s / %s / %s)",
                 gw_s, rem_s, far_s);
        return -1;
    }
    if (run->cfg.gw_tunnel_ip == run->cfg.remote_tunnel_ip) {
        snprintf(err, err_len,
                 "the two gateways share one tunnel address");
        return -1;
    }
    if (parse_mappings(json, &run->map, err, err_len) != 0) return -1;
    run->cfg.map = &run->map;
    if (json_get_string(json, "filter", run->filter,
                        sizeof(run->filter)) != 0 ||
        run->filter[0] == '\0') {
        /* Rebuild it: dst in {virt..., farVirt, gwTunnel} or src ==
         * remoteTunnel, IPv4 only. Must match nat-gateway.js.
         * `off` is clamped after every append so the size argument
         * below can never underflow. */
        size_t off = 0;
        int i, n;
        off += (size_t)snprintf(run->filter + off,
                                sizeof(run->filter) - off, "(");
        if (off >= sizeof(run->filter)) off = sizeof(run->filter) - 1;
        for (i = 0; i < run->map.count; i++) {
            char ip[32];
            tvnat_ip_format(run->map.items[i].virt, ip, sizeof(ip));
            off += (size_t)snprintf(run->filter + off,
                                    sizeof(run->filter) - off,
                                    "%sip.DstAddr == %s",
                                    i ? " or " : "", ip);
            if (off >= sizeof(run->filter)) off = sizeof(run->filter) - 1;
        }
        {
            char ip[32];
            tvnat_ip_format(run->cfg.far_virt_ip, ip, sizeof(ip));
            off += (size_t)snprintf(run->filter + off,
                                    sizeof(run->filter) - off,
                                    " or ip.DstAddr == %s", ip);
            if (off >= sizeof(run->filter)) off = sizeof(run->filter) - 1;
            tvnat_ip_format(run->cfg.gw_tunnel_ip, ip, sizeof(ip));
            off += (size_t)snprintf(run->filter + off,
                                    sizeof(run->filter) - off,
                                    " or ip.DstAddr == %s", ip);
            if (off >= sizeof(run->filter)) off = sizeof(run->filter) - 1;
        }
        {
            char ip[32];
            tvnat_ip_format(run->cfg.remote_tunnel_ip, ip, sizeof(ip));
            n = snprintf(run->filter + off, sizeof(run->filter) - off,
                         " or ip.SrcAddr == %s) and ip", ip);
            off += (size_t)(n > 0 ? n : 0);
        }
        (void)off;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static void log_json(const char *level, const char *fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    /* Escape the two characters that would break the JSON line. */
    {
        char esc[1024];
        size_t i, o = 0;
        for (i = 0; msg[i] && o + 2 < sizeof(esc); i++) {
            if (msg[i] == '"' || msg[i] == '\\') esc[o++] = '\\';
            esc[o++] = msg[i];
        }
        esc[o] = '\0';
        printf("{\"type\":\"log\",\"level\":\"%s\",\"msg\":\"%s\"}\n", level,
               esc);
    }
    fflush(stdout);
}

static void print_stats(uint64_t packets, uint64_t translated,
                        uint64_t passed, uint64_t dropped) {
    printf("{\"type\":\"stats\",\"packets\":%llu,\"translated\":%llu,"
           "\"passed\":%llu,\"dropped\":%llu}\n",
           (unsigned long long)packets,
           (unsigned long long)translated,
           (unsigned long long)passed,
           (unsigned long long)dropped);
    fflush(stdout);
}

/* The interface index of the adapter that owns `tunnel_ip` (the
 * Wintun interface). 0 when not found — steering is then skipped
 * and a warning is logged, rather than sending packets out the
 * wrong interface. */
static uint32_t find_tunnel_ifindex(uint32_t tunnel_ip) {
    ULONG size = 0;
    PIP_ADAPTER_ADDRESSES addrs = NULL;
    uint32_t found = 0;
    /* tunnel_ip is network byte order as on the wire; the adapter
     * addresses come back in the same byte order, so compare the
     * raw DWORDs after converting through the same parse. */
    DWORD want = ((tunnel_ip >> 24) & 0xFF) |
                 (((tunnel_ip >> 16) & 0xFF) << 8) |
                 (((tunnel_ip >> 8) & 0xFF) << 16) |
                 ((tunnel_ip & 0xFF) << 24);
    if (GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &size) !=
            ERROR_BUFFER_OVERFLOW ||
        size == 0)
        return 0;
    addrs = (PIP_ADAPTER_ADDRESSES)malloc(size);
    if (!addrs) return 0;
    if (GetAdaptersAddresses(AF_INET, 0, NULL, addrs, &size) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES a;
        for (a = addrs; a; a = a->Next) {
            PIP_ADAPTER_UNICAST_ADDRESS u;
            for (u = a->FirstUnicastAddress; u; u = u->Next) {
                struct sockaddr_in *sin =
                    (struct sockaddr_in *)u->Address.lpSockaddr;
                if (sin && sin->sin_family == AF_INET &&
                    sin->sin_addr.S_un.S_addr == want) {
                    found = a->IfIndex;
                    break;
                }
            }
            if (found) break;
        }
    }
    free(addrs);
    return found;
}

/* stdin reader thread: {"type":"stop"} or EOF means shut down.
 * WinDivertShutdown(RECV) unblocks the WinDivertRecv in main. */
static DWORD WINAPI stdin_thread(LPVOID arg) {
    char line[8192];
    (void)arg;
    while (fgets(line, sizeof(line), stdin)) {
        if (strstr(line, "\"stop\"")) break;
    }
    InterlockedExchange(&g_stop, 1);
    if (g_handle != INVALID_HANDLE_VALUE)
        WinDivertShutdown(g_handle, WINDIVERT_SHUTDOWN_RECV);
    return 0;
}

static int read_config_line(char *buf, size_t len, const char *file) {
    if (file) {
        FILE *f = fopen(file, "rb");
        size_t n;
        if (!f) return -1;
        n = fread(buf, 1, len - 1, f);
        fclose(f);
        buf[n] = '\0';
        /* Take the first line only. */
        {
            char *nl = strchr(buf, '\n');
            if (nl) *nl = '\0';
        }
        return buf[0] ? 0 : -1;
    }
    if (!fgets(buf, (int)len, stdin)) return -1;
    {
        size_t n = strlen(buf);
        while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
            buf[--n] = '\0';
    }
    return buf[0] ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    const char *config_file = NULL;
    int check_only = 0;
    int i;
    char json[65536];
    char err[512];
    tvnat_run_cfg_t run;
    HANDLE handle;
    tvnat_flows_t flows;
    uint64_t packets = 0, translated = 0, passed = 0, dropped = 0;
    uint64_t last_stats_ms = 0, now_ms = 0;
    unsigned char *pkt;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("tvnat %s\n", TVNAT_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--check") == 0) {
            check_only = 1;
        } else if (strcmp(argv[i], "--config-file") == 0 && i + 1 < argc) {
            config_file = argv[++i];
        } else {
            fprintf(stderr, "tvnat: unknown argument '%s'\n", argv[i]);
            fprintf(stderr,
                    "usage: tvnat.exe [--config-file <path>] [--check] "
                    "[--version]\n");
            return 2;
        }
    }

    if (read_config_line(json, sizeof(json), config_file) != 0) {
        printf("{\"type\":\"error\",\"msg\":\"no config line on stdin\"}\n");
        fflush(stdout);
        return 2;
    }
    if (parse_config(json, &run, err, sizeof(err)) != 0) {
        printf("{\"type\":\"error\",\"msg\":\"bad config: %s\"}\n", err);
        fflush(stdout);
        return 2;
    }

    if (check_only) {
        /* Validate the filter without touching the driver. */
        char obj[8192];
        const char *err_str = NULL;
        UINT err_pos = 0;
        if (!WinDivertHelperCompileFilter(run.filter,
                                          WINDIVERT_LAYER_NETWORK, obj,
                                          sizeof(obj), &err_str,
                                          &err_pos)) {
            printf("{\"type\":\"error\",\"msg\":\"bad filter at %u: %s\"}\n",
                   err_pos, err_str ? err_str : "?");
            fflush(stdout);
            return 2;
        }
        printf("{\"type\":\"ready\",\"filter\":\"%s\",\"mappings\":%d,"
               "\"check\":true}\n",
               run.filter, run.map.count);
        fflush(stdout);
        return 0;
    }

    run.tunnel_ifidx = find_tunnel_ifindex(run.cfg.gw_tunnel_ip);
    if (run.tunnel_ifidx == 0) {
        log_json("error",
                 "could not find the tunnel interface for the "
                 "gateway address — LAN->tunnel packets will not be "
                 "steered into the tunnel");
    }

    handle = WinDivertOpen(run.filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED) {
            printf("{\"type\":\"error\",\"msg\":\"WinDivert needs "
                   "administrator permission (access denied opening "
                   "the handle). Run TechVision as administrator "
                   "once.\"}\n");
        } else if (e == ERROR_FILE_NOT_FOUND) {
            printf("{\"type\":\"error\",\"msg\":\"WinDivert driver not "
                   "found (WinDivert64.sys missing next to "
                   "WinDivert.dll).\"}\n");
        } else {
            printf("{\"type\":\"error\",\"msg\":\"WinDivertOpen failed "
                   "(error %lu). Is another NAT helper already "
                   "running?\"}\n",
                   (unsigned long)e);
        }
        fflush(stdout);
        return 1;
    }
    g_handle = handle;

    /* A reader thread watches stdin for {"type":"stop"} / EOF. */
    {
        HANDLE th = CreateThread(NULL, 0, stdin_thread, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }

    memset(&flows, 0, sizeof(flows));
    pkt = (unsigned char *)malloc(TVNAT_MAX_PACKET);
    if (!pkt) {
        printf("{\"type\":\"error\",\"msg\":\"out of memory\"}\n");
        fflush(stdout);
        WinDivertClose(handle);
        return 1;
    }
    printf("{\"type\":\"ready\",\"filter\":\"%s\",\"mappings\":%d}\n",
           run.filter, run.map.count);
    fflush(stdout);
    log_json("info", "NAT helper running (%d mappings, tunnel ifindex %lu)",
             run.map.count, (unsigned long)run.tunnel_ifidx);
    last_stats_ms = GetTickCount64();

    for (;;) {
        WINDIVERT_ADDRESS addr;
        UINT recv_len = 0;
        uint8_t proto = 0;
        uint32_t src = 0, dst = 0;
        uint16_t sport = 0, dport = 0;
        int from_tunnel, rc;
        (void)proto;
        (void)sport;
        (void)dport;
        if (!WinDivertRecv(handle, pkt, TVNAT_MAX_PACKET, &recv_len,
                           &addr)) {
            if (InterlockedCompareExchange(&g_stop, 0, 0)) break;
            {
                DWORD e = GetLastError();
                if (e == ERROR_NO_DATA || e == ERROR_INVALID_HANDLE)
                    break;
                log_json("error", "WinDivertRecv failed (error %lu)",
                         (unsigned long)e);
            }
            break;
        }
        packets++;
        now_ms = GetTickCount64();
        if (tvnat_packet_fields(pkt, recv_len, &proto, &src, &dst,
                                &sport, &dport) != 0) {
            /* Not a parseable IPv4 packet: pass it through rather
             * than dropping someone else's traffic. (The filter
             * should never deliver one, but defence in depth.) */
            UINT sent = 0;
            if (WinDivertSend(handle, pkt, recv_len, &sent, &addr))
                passed++;
            else
                dropped++;
            continue;
        }
        /* Which side did it come from? The tunnel side is the one
         * whose packets carry the remote gateway's tunnel address
         * as source, or this gateway's tunnel address as
         * destination. Everything else matched the filter because
         * it is addressed to a virtual address — the LAN side. */
        from_tunnel = (src == run.cfg.remote_tunnel_ip ||
                       dst == run.cfg.gw_tunnel_ip);
        rc = tvnat_translate(pkt, recv_len, from_tunnel, &run.cfg,
                             &flows, now_ms);
        if (rc == 1) {
            UINT sent = 0;
            /* The core already fixed the checksums on rewrite; the
             * WinDivert helper recalculates them authoritatively. */
            WinDivertHelperCalcChecksums(pkt, recv_len, &addr, 0);
            if (!from_tunnel && run.tunnel_ifidx != 0) {
                /* LAN -> tunnel: steer out the tunnel interface —
                 * the local routing table would otherwise send this
                 * (colliding) destination back out the LAN. */
                addr.Outbound = 1;
                addr.Network.IfIdx = run.tunnel_ifidx;
                addr.Network.SubIfIdx = 0;
            }
            if (WinDivertSend(handle, pkt, recv_len, &sent, &addr))
                translated++;
            else
                dropped++;
        } else if (rc == 0) {
            UINT sent = 0;
            if (WinDivertSend(handle, pkt, recv_len, &sent, &addr))
                passed++;
            else
                dropped++;
        } else {
            dropped++; /* reply with no live flow: never forward it */
        }
        if (now_ms - last_stats_ms >= TVNAT_STATS_MS) {
            print_stats(packets, translated, passed, dropped);
            last_stats_ms = now_ms;
        }
    }

    print_stats(packets, translated, passed, dropped);
    free(pkt);
    WinDivertClose(handle);
    g_handle = INVALID_HANDLE_VALUE;
    return 0;
}

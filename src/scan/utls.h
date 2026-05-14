// SPDX-License-Identifier: GPL-3.0-or-later
// dual-flavored TLS handshake probe.
//
// per port the orchestrator runs TWO TLS handshakes from two different
// ClientHello fingerprints:
//   * "chrome": a byte-accurate Chrome 131 ClientHello (see chrome_ch.h) sent
//     over a raw socket. GREASE at the spec positions, the Chrome extension
//     set, GREASE key_share, padding extension. handshake_completed here
//     means the server answered with a real ServerHello (not an alert, not
//     HelloRetryRequest) i.e. it accepted the Chrome fingerprint. the TLS 1.3
//     key schedule is not run, so this flavor has no peer cert.
//   * "openssl": the same OpenSSL ctx the rest of the tool uses
//     (TLS_client_method, no extra options). full handshake, so it does
//     recover the peer cert.
//
// for each probe we capture the raw ClientHello bytes (what we sent) and the
// ServerHello bytes (what the server returned), then feed them through ja4.h
// to produce JA4 and JA4S.
//
// the diff is the diagnostic:
//   * chrome accepted, openssl rejected -> server enforces a uTLS / browser
//     fingerprint profile (the main 2026 Reality detection signal).
//   * different JA4S between the two flavors -> server adapts its ServerHello
//     to client JA3 -> reality / utls-aware steering.
//   * different cert sha256 (only observable when both complete via the
//     openssl path) -> hard reality cert enforcement.
#pragma once

#include "ja4.h"

#include <cstdint>
#include <string>
#include <vector>

struct UtlsProbeResult {
    bool        ok = false;
    bool        handshake_completed = false;
    std::string err;
    std::string flavor;                 // "chrome" or "openssl"
    int         tls_version = 0;        // negotiated, decoded from real_version
    std::string cipher;                 // negotiated (text, e.g. TLS_AES_128_GCM_SHA256)
    std::string alpn;                   // negotiated ALPN
    std::string cert_sha256;
    long long   handshake_ms = 0;

    // raw bytes of CH/SH first message captured by msg_callback
    std::vector<uint8_t> ch_bytes;
    std::vector<uint8_t> sh_bytes;

    // parsed forms + JA4 strings (filled if parse succeeds)
    ClientHelloFp ch_fp;
    ServerHelloFp sh_fp;
    std::string   ja4;
    std::string   ja4s;
};

UtlsProbeResult utls_probe_chrome (const std::string& ip, int port,
                                   const std::string& sni,
                                   int to_ms = 5000);

UtlsProbeResult utls_probe_openssl(const std::string& ip, int port,
                                   const std::string& sni,
                                   int to_ms = 5000);

struct UtlsDualProbe {
    UtlsProbeResult chrome;
    UtlsProbeResult openssl;
    bool        both_completed   = false;
    bool        ja4s_differs     = false;   // server SH differs between flavors
    bool        cert_differs     = false;   // cert sha256 differs between flavors
    bool        only_chrome_ok   = false;   // chrome handshake passed, openssl rejected
    bool        only_openssl_ok  = false;   // openssl passed, chrome rejected
    std::string verdict;                    // short human-readable conclusion
};

UtlsDualProbe utls_dual_probe(const std::string& ip, int port,
                              const std::string& sni);
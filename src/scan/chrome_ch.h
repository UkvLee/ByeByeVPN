// SPDX-License-Identifier: GPL-3.0-or-later
// byte-accurate Chrome 131 ClientHello construction.
//
// the v2.5.9 "chrome-flavored" probe approximated Chrome by tweaking an
// OpenSSL SSL_CTX (cipher list, groups, sigalgs order). that is NOT a real
// Chrome hello: the extension order is OpenSSL's, there is no GREASE
// injection, no padding extension, no GREASE key_share. a uTLS-enforcing
// Reality server tells the two apart and the v2.5.9 probe could not.
//
// this builder emits the actual wire bytes Chrome sends: GREASE values at
// the spec positions (cipher list, supported_groups, key_share,
// supported_versions, two bookend extensions), the Chrome extension set,
// a GREASE-prefixed x25519 key_share, and the padding extension sized the
// way BoringSSL sizes it. the 32-byte random, the 32-byte legacy session
// id, the key_share public value and the GREASE selections are randomized
// per call.
//
// one extension is intentionally omitted: encrypted_client_hello (0xfe0d).
// a GREASE ECH carries an HPKE-shaped body Chrome 131 fills from its ECH
// config cache; emitting a static one would be LESS accurate than omitting
// it. without ECH the JA4 is t13d1516h2 (Chrome ~120-130), still a real
// browser fingerprint, never the openssl-default JA4.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

// build a Chrome-131-class ClientHello for the given SNI.
// returns a complete TLS plaintext record (5-byte record header followed by
// the handshake message) ready to write straight to a connected socket.
std::vector<uint8_t> build_chrome131_clienthello(const std::string& sni);

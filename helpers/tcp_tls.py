tls_content_type_map = {
    0x16: "TLS Handshake",
    0x14: "TLS ChangeCipherSpec",
    0x15: "TLS Alert",
    0x17: "TLS Application data",
    0x18: "TLS Heartbeat"
}

tls_version_map = {
    (0x03, 0x01): "TLS 1.0",
    (0x03, 0x02): "TLS 1.1",
    (0x03, 0x03): "TLS 1.2",
    (0x03, 0x04): "TLS 1.3"
}

tls_handshake_type_map = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x0b: "Certificate",
    0x0c: "ServerKeyExchange",
    0x0e: "ServerHelloDone",
    0x10: "ClientKeyExchange",
    0x14: "Finished"
}

cipher_suite_map = {
    (0x00, 0x2f): "TLS_RSA_WITH_AES_128_CBC_SHA",
    (0x00, 0x35): "TLS_RSA_WITH_AES_256_CBC_SHA",
    (0x00, 0x3c): "TLS_RSA_WITH_AES_128_CBC_SHA256",
    (0x00, 0x9c): "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    (0xc0, 0x13): "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    (0xc0, 0x2f): "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    (0xc0, 0x30): "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    (0x13, 0x01): "TLS_AES_128_GCM_SHA256",
    (0x13, 0x02): "TLS_AES_256_GCM_SHA384",
    (0x13, 0x03): "TLS_CHACHA20_POLY1305_SHA256",
    (0xc0, 0x2c): "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    (0xc0, 0x2b): "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    (0xcc, 0xa8): "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    (0xcc, 0xa9): "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    (0xc0, 0x14): "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    (0x00, 0x9d): "TLS_RSA_WITH_AES_256_GCM_SHA384",
    (0xc0, 0x24): "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    (0xc0, 0x23): "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    (0xc0, 0x28): "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    (0xc0, 0x27): "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    (0xc0, 0x0a): "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    (0xc0, 0x09): "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    (0x00, 0x3d): "TLS_RSA_WITH_AES_256_CBC_SHA256"
}

extensions_map = {
    (0x00, 0x00): "server_name",
    (0x00, 0x0a): "supported_groups",
    (0x00, 0x0d): "signature_algorithms",
    (0x00, 0x10): "ALPN",
    (0x00, 0x2b): "supported_versions",
    (0x00, 0x33): "key_share",
    (0x00, 0x23): "session_ticket",
    (0xff, 0x01): "renegotiation_info",
    (0x00, 0x11): "status_request_v2",
    (0x00, 0x35): "connection_id (deprecated)",
    (0x00, 0x21): "tls_cert_with_extern_psk"
}
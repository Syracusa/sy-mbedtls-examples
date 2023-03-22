#ifndef CONF_H
#define CONF_H

#include <unistd.h>

#include "mbedtls/ssl_ciphersuites.h"

#define SERVER_ADDR "192.168.1.111"
// #define SERVER_ADDR "127.0.0.1"

#define USE_CLIENT_AUTH 1
#define USE_FORCED_CIPHER 1

// #define FORCED_CIPHER                MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
#define FORCED_CIPHER                   MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
#define FORCED_CIPHER_TLS_VERSION   MBEDTLS_SSL_VERSION_TLS1_2

#endif

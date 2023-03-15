/*
Original sourece code from
https://github.com/Mbed-TLS/mbedtls/blob/development/programs/ssl/dtls_client.c
*/
#include <string.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"

#include "conf.h"

#define SERVER_PORT "4433"
#define SERVER_NAME "Server"


#define MESSAGE "Echo this"

#define READ_TIMEOUT_MS 10000
#define MAX_RETRY 5

#define DEBUG_LEVEL 4

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void)level);

    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

int main(int argc, char *argv[])
{
    int ret, len;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers = "dtls_client";
    int retry_left = MAX_RETRY;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_timing_delay_context timer;

#if USE_CLIENT_AUTH
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;

    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);
#else
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt_init(&cacert);
#endif

    ((void)argc);
    ((void)argv);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    psa_crypto_init();

    printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    printf(" ok\n");

    /*
     * 0. Load certificates
     */
    printf("  . Loading the CA root certificate ...");
    fflush(stdout);

#if USE_CLIENT_AUTH

    const char *clientcertpath;
    const char *clientpkeypath;
    const char *cacertpath;

    if (access("../../gencert/certs/client.cert.pem", F_OK) == 0){
        clientcertpath = "../../gencert/certs/client.cert.pem";
    } else if (access("./client.cert.pem", F_OK) == 0) {
        clientcertpath = "./client.cert.pem";
    } else {
        fprintf(stderr, "No client cert found.\n");
        goto exit;
    }

    if (access("../../gencert/certs/ca.cert.pem", F_OK) == 0){
        cacertpath = "../../gencert/certs/ca.cert.pem";
    } else if (access("./ca.cert.pem", F_OK) == 0) {
        cacertpath = "./ca.cert.pem";
    } else {
        fprintf(stderr, "No ca cert found.\n");
        goto exit;
    }

    if (access("../../gencert/private/client.pem", F_OK) == 0){
        clientpkeypath ="../../gencert/private/client.pem";
    } else if (access("./client.pem", F_OK) == 0) {
        clientpkeypath = "./client.pem";
    } else {
        fprintf(stderr, "No client key found.\n");
        goto exit;
    }

    ret = mbedtls_x509_crt_parse_file(&clicert, clientcertpath);
    if (ret != 0)
    {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse_file(&clicert, cacertpath);
    if (ret != 0)
    {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_pk_parse_keyfile(&pkey,
                                   clientpkeypath,
                                   NULL,
                                   mbedtls_ctr_drbg_random,
                                   &ctr_drbg);
#else
    ret = mbedtls_x509_crt_parse_file(&cacert, "../../gencert/certs/ca.cert.pem");
    if (ret != 0)
    {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }
#endif

    printf(" ok (%d skipped)\n", ret);

    /*
     * 1. Start the connection
     */
    printf("  . Connecting to udp/%s/%s...", SERVER_ADDR, SERVER_PORT);
    fflush(stdout);

    if ((ret = mbedtls_net_connect(&server_fd, SERVER_ADDR,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_UDP)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    printf("  . Setting up the DTLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_ssl_conf_read_timeout(&conf, READ_TIMEOUT_MS);

#if USE_FORCED_CIPHER
    mbedtls_ssl_conf_max_tls_version(&conf, FORCED_CIPHER_TLS_VERSION);
    mbedtls_ssl_conf_min_tls_version(&conf, FORCED_CIPHER_TLS_VERSION);

    const int forced_cipher[] = {FORCED_CIPHER, 0};
    mbedtls_ssl_conf_ciphersuites(&conf, forced_cipher);
#endif

#if USE_CLIENT_AUTH
    mbedtls_ssl_conf_ca_chain(&conf, clicert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }
#else
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd,
                        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    printf(" ok\n");

    /*
     * 4. Handshake
     */
    printf("  . Performing the DTLS handshake...");
    fflush(stdout);

    do
        ret = mbedtls_ssl_handshake(&ssl);
    while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int)-ret);
        goto exit;
    }

    printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    printf("  . Verifying peer X.509 certificate...");

    /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
     * handshake would not succeed if the peer's cert is bad.  Even if we used
     * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    {
#if !defined(MBEDTLS_X509_REMOVE_INFO)
        char vrfy_buf[512];
#endif

        printf(" failed\n");

#if !defined(MBEDTLS_X509_REMOVE_INFO)
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        printf("%s\n", vrfy_buf);
#endif
    }
    else
        printf("\nmbedtls_ssl_get_verify_result ok\n");

    /* Handshake done. Check cipher. */
    printf("Negotiated cipher : %s(%s)",
           mbedtls_ssl_get_ciphersuite(&ssl),
           mbedtls_ssl_get_version(&ssl));

    /*
     * 6. Write the echo request
     */
send_request:
    printf("  > Write to server:");
    fflush(stdout);

    len = sizeof(MESSAGE) - 1;

    do
        ret = mbedtls_ssl_write(&ssl, (unsigned char *)MESSAGE, len);
    while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret < 0)
    {
        printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
        goto exit;
    }

    len = ret;
    printf(" %d bytes written\n\n%s\n\n", len, MESSAGE);

    /*
     * 7. Read the echo response
     */
    printf("  < Read from server:");
    fflush(stdout);

    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));

    do
        ret = mbedtls_ssl_read(&ssl, buf, len);
    while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret <= 0)
    {
        switch (ret)
        {
        case MBEDTLS_ERR_SSL_TIMEOUT:
            printf(" timeout\n\n");
            if (retry_left-- > 0)
                goto send_request;
            goto exit;

        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            printf(" connection was closed gracefully\n");
            ret = 0;
            goto close_notify;

        default:
            printf(" mbedtls_ssl_read returned -0x%x\n\n", (unsigned int)-ret);
            goto exit;
        }
    }

    len = ret;
    printf(" %d bytes read\n\n%s\n\n", len, buf);

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    printf("  . Closing the connection...");

    /* No error checking, the connection might be closed already */
    do
        ret = mbedtls_ssl_close_notify(&ssl);
    while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    ret = 0;

    printf(" done\n");

    /*
     * 9. Final clean-ups and exit
     */
exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&server_fd);
#if USE_CLIENT_AUTH
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&clicert);
#else
    mbedtls_x509_crt_free(&cacert);
#endif
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}

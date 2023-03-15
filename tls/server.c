
/*
Original sourece code from
https://github.com/Mbed-TLS/mbedtls/blob/development/programs/ssl/dtls_server.c
*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#include "conf.h"

#define READ_TIMEOUT_MS 10000 /* 10 seconds */
#define DEBUG_LEVEL 4

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void)level);

    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

int main(void)
{
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "dtls_server";
    unsigned char client_ip[16] = {0};
    size_t cliip_len;
    mbedtls_ssl_cookie_ctx cookie_ctx;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
    mbedtls_timing_delay_context timer;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_cookie_init(&cookie_ctx);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    psa_crypto_init();
    /*
     * 1. Seed the RNG
     */
    printf("  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    printf(" ok\n");

    /*
     * 2. Load the certificates and private RSA key
     */
    printf("\n  . Loading the server cert. and key...");
    fflush(stdout);

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */


    const char* servercertpath;
    const char* serverpkeypath;
    const char* cacertpath;

    if (access("../../gencert/certs/server.cert.pem", F_OK) == 0){
        servercertpath = "../../gencert/certs/server.cert.pem";
    } else if (access("./server.cert.pem", F_OK) == 0) {
        servercertpath = "./server.cert.pem";
    } else {
        fprintf(stderr, "No server cert found.\n");
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

    if (access("../../gencert/private/server.pem", F_OK) == 0){
        serverpkeypath ="../../gencert/private/server.pem";
    } else if (access("./server.pem", F_OK) == 0) {
        serverpkeypath = "./server.pem";
    } else {
        fprintf(stderr, "No server key found.\n");
        goto exit;
    }

    ret = mbedtls_x509_crt_parse_file(&srvcert, servercertpath);
    if (ret != 0)
    {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_x509_crt_parse_file(&srvcert,cacertpath);
    if (ret != 0)
    {
        printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_pk_parse_keyfile(&pkey,
                                   serverpkeypath,
                                   NULL,
                                   mbedtls_ctr_drbg_random,
                                   &ctr_drbg);
    if (ret != 0)
    {
        printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    printf(" ok\n");

    /*
     * 3. Setup the "listening" UDP socket
     */
    printf("  . Bind on udp/%s/4433 ...", SERVER_ADDR);
    fflush(stdout);

    if ((ret = mbedtls_net_bind(&listen_fd, SERVER_ADDR, "4433", MBEDTLS_NET_PROTO_UDP)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    printf("  . Setting up the DTLS data...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

#if USE_CLIENT_AUTH
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#endif
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_ssl_conf_read_timeout(&conf, READ_TIMEOUT_MS);

    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_cookie_setup(&cookie_ctx,
                                        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                  &cookie_ctx);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  client_ip, sizeof(client_ip), &cliip_len)) != 0)
    {
        printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    /* For HelloVerifyRequest cookies */
    if ((ret = mbedtls_ssl_set_client_transport_id(&ssl,
                                                   client_ip, cliip_len)) != 0)
    {
        printf(" failed\n  ! "
               "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n",
               (unsigned int)-ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd,
                        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    printf(" ok\n");

    /*
     * 5. Handshake
     */
    printf("  . Performing the DTLS handshake...");
    fflush(stdout);

    do
    {
        ret = mbedtls_ssl_handshake(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
    {
        printf(" hello verification requested\n");
        ret = 0;
        goto reset;
    }
    else if (ret != 0)
    {
        printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int)-ret);
        goto reset;
    }

    printf(" ok\n");

#if USE_CLIENT_AUTH
    uint32_t flags;
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
#endif

    /* Handshake done. Check cipher. */
    printf("Negotiated cipher : %s(%s)",
           mbedtls_ssl_get_ciphersuite(&ssl),
           mbedtls_ssl_get_version(&ssl));

    /*
     * 6. Read the echo Request
     */
    printf("  < Read from client:");
    fflush(stdout);

    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));

    do
    {
        ret = mbedtls_ssl_read(&ssl, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret <= 0)
    {
        switch (ret)
        {
        case MBEDTLS_ERR_SSL_TIMEOUT:
            printf(" timeout\n\n");
            goto reset;

        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            printf(" connection was closed gracefully\n");
            ret = 0;
            goto close_notify;

        default:
            printf(" mbedtls_ssl_read returned -0x%x\n\n", (unsigned int)-ret);
            goto reset;
        }
    }

    len = ret;
    printf(" %d bytes read\n\n%s\n\n", len, buf);

    /*
     * 7. Write the 200 Response
     */
    printf("  > Write to client:");
    fflush(stdout);

    do
    {
        ret = mbedtls_ssl_write(&ssl, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret < 0)
    {
        printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
        goto exit;
    }

    len = ret;
    printf(" %d bytes written\n\n%s\n\n", len, buf);

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    printf("  . Closing the connection...");

    /* No error checking, the connection might be closed already */
    do
    {
        ret = mbedtls_ssl_close_notify(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    ret = 0;

    printf(" done\n");

    goto reset;

    /*
     * Final clean-ups and exit
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

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_cookie_free(&cookie_ctx);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    /* Shell can not handle large exit numbers -> 1 for errors */
    if (ret < 0)
    {
        ret = 1;
    }
    return 0;
}
#include "stream.h"
#include "socks5.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TOR_PROXY_HOST  "127.0.0.1"
#define TOR_PROXY_PORT  9050
#define I2P_PROXY_HOST  "127.0.0.1"
#define I2P_PROXY_PORT  4447

void stream_result_free(stream_result_t *r) {
    if (r && r->data) {
        free(r->data);
        r->data = NULL;
        r->data_len = 0;
    }
}

/* CLEARNET/SKHORON пока не реализованы реальным транспортом - честная
 * заглушка вместо непроверенного кода. Когда будет готов настоящий
 * QUIC-клиент (собранный и протестированный, не "на веру"), эта функция
 * заменяется на реальный вызов. */
static stream_result_t stream_open_not_implemented(const target_t *t) {
    stream_result_t r = {0};
    r.ok = 0;
    r.transport = STREAM_TRANSPORT_NONE;
    r.fd = -1;
    snprintf(r.error, sizeof(r.error),
             "не реализовано: %s:%d (сеть=%s) - QUIC-транспорт для CLEARNET/SKHORON ещё не написан",
             t->host, t->port, router_network_name(t->net));
    return r;
}

stream_result_t stream_open(const target_t *target, int dry_run) {
    stream_result_t r = {0};
    r.fd = -1;

    switch (target->net) {
        case NET_TOR:
        case NET_I2P: {
            const char *proxy_host = (target->net == NET_TOR) ? TOR_PROXY_HOST : I2P_PROXY_HOST;
            int proxy_port         = (target->net == NET_TOR) ? TOR_PROXY_PORT : I2P_PROXY_PORT;

            if (dry_run) {
                r.ok = 1;
                r.transport = STREAM_TRANSPORT_NONE;
                snprintf(r.error, sizeof(r.error),
                         "[DRY-RUN] отправил бы SOCKS5 CONNECT на %s:%d -> %s:%d",
                         proxy_host, proxy_port, target->host, target->port);
                return r;
            }

            int fd = socks5_connect(proxy_host, proxy_port,
                                     target->host, target->port,
                                     r.error, sizeof(r.error));
            if (fd < 0) { r.ok = 0; return r; }
            r.ok = 1;
            r.transport = STREAM_TRANSPORT_TCP_FD;
            r.fd = fd;
            return r;
        }

        case NET_CLEARNET:
        case NET_SKHORON:
        default:
            return stream_open_not_implemented(target);
    }
}
#ifndef SKHORON_STREAM_H
#define SKHORON_STREAM_H

#include "router.h"
#include <stddef.h>

/* Что именно представляет собой открытый стрим - нужно, чтобы вызывающий
 * код не пытался обращаться с QUIC-стримом как с обычным TCP-сокетом
 * (у них разная семантика: TCP fd можно read()/write() напрямую,
 * QUIC-стрим живёт внутри ngtcp2_conn и так не читается). */
typedef enum {
    STREAM_TRANSPORT_NONE = 0,  /* стрим не открыт (см. ok/error)      */
    STREAM_TRANSPORT_TCP_FD,    /* обычный сокет, годится read()/write() */
    STREAM_TRANSPORT_QUIC       /* QUIC bidi-stream, см. data/data_len  */
} stream_transport_t;

/* Результат открытия стрима.
 *
 * ВАЖНО: error - это ТОЛЬКО диагностическое сообщение (для логов/UI),
 * никогда не полезная нагрузка ответа. Данные, полученные по QUIC (пока
 * это blocking one-shot клиент, не полноценный многопоточный стрим),
 * лежат в data/data_len - отдельно, чтобы не путать текст ошибки с
 * содержимым ответа (это раньше было перепутано - error использовался
 * для обоих случаев). */
typedef struct {
    int  ok;                    /* 1 = успех, 0 = ошибка */
    stream_transport_t transport;
    int  fd;                    /* валиден только если transport == STREAM_TRANSPORT_TCP_FD */
    unsigned char *data;        /* heap-буфер ответа для STREAM_TRANSPORT_QUIC, либо NULL */
    size_t data_len;
    char error[512];
} stream_result_t;

/* Освобождает data, если она была выделена (no-op, если data == NULL).
 * Вызывающий код должен звать это для каждого stream_result_t с
 * transport == STREAM_TRANSPORT_QUIC после того, как данные больше
 * не нужны. */
void stream_result_free(stream_result_t *r);

/* Открывает "стрим" к target на нужной сети.
 *
 * NET_TOR / NET_I2P -> реально подключается по протоколу SOCKS5
 *   к локальному процессу tor/i2pd (порты 9050 / 4447) и просит
 *   его сделать CONNECT до target->host:target->port.
 *   Это рабочий, полностью реализованный путь (transport = TCP_FD).
 *
 * NET_CLEARNET / NET_SKHORON -> ПОКА НЕ РЕАЛИЗОВАНО. Возвращает
 *   ok=0 с понятным текстом ошибки. STREAM_TRANSPORT_QUIC зарезервирован
 *   под будущую реализацию (см. enum выше), но сейчас в этот код путь
 *   ни разу не заходит.
 */
stream_result_t stream_open(const target_t *target, int dry_run);

#endif
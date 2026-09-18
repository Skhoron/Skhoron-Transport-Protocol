#ifndef SKHORON_ROUTER_H
#define SKHORON_ROUTER_H

/* Тип сети, в которую нужно отправить запрос.
   Определяется автоматически по домену/ссылке. */
typedef enum {
    NET_CLEARNET = 0,  /* обычный интернет: HTTPS, HTTP, почта, любой IP:порт */
    NET_TOR,           /* *.onion -> локальный tor SOCKS5 (127.0.0.1:9050)   */
    NET_I2P,           /* *.i2p   -> локальный i2pd SOCKS5 (127.0.0.1:4447) */
    NET_SKHORON        /* *.skh / Public-ID -> внутренняя P2P-сеть Skhoron */
} network_type_t;

/* Схема из URL — нужна, чтобы подставлять правильный порт по умолчанию
   (http->80, https->443), а не всегда 443. */
typedef enum {
    SCHEME_UNKNOWN = 0,
    SCHEME_HTTP,
    SCHEME_HTTPS
} scheme_type_t;

/* Разобранный адрес назначения */
typedef struct {
    char host[256];          /* без квадратных скобок, даже для IPv6 */
    int  port;                /* -1 если не указан явно в URL */
    int  is_ipv6_literal;     /* 1, если host - это "голый" IPv6-литерал */
    scheme_type_t scheme;
    network_type_t net;
} target_t;

typedef enum {
    ROUTER_OK = 0,
    ROUTER_ERR_NULL_ARG,
    ROUTER_ERR_EMPTY_AUTHORITY,
    ROUTER_ERR_TOO_LONG,
    ROUTER_ERR_BAD_IPV6_LITERAL,
    ROUTER_ERR_BAD_PORT
} router_error_t;

/* Определяет сеть по хосту (суффикс/формат домена).
   Возвращает NET_CLEARNET по умолчанию, если ничего не подошло. */
network_type_t router_detect_network(const char *host);

/* Разбирает URL вида "scheme://host:port/path" или "scheme://[ipv6]:port/path"
   в target_t. target->port = -1, если порт не указан явно в URL -
   вызывающий код должен сам подставить порт по умолчанию через
   router_default_port(target->scheme) или свою логику. */
router_error_t router_parse_url(const char *url, target_t *out);

/* Порт по умолчанию для схемы: http->80, https->443, иначе 443
   (безопасный дефолт для схем, которые мы не разбираем явно). */
int router_default_port(scheme_type_t scheme);

/* Человекочитаемое имя сети - для логов/UI */
const char *router_network_name(network_type_t net);
const char *router_error_string(router_error_t err);

#endif
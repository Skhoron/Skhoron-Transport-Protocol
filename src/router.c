#define _POSIX_C_SOURCE 200809L
#include "router.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

static int ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s), lsuf = strlen(suffix);
    if (lsuf > ls) return 0;
    const char *tail = s + (ls - lsuf);
    for (size_t i = 0; i < lsuf; i++) {
        if (tolower((unsigned char)tail[i]) != tolower((unsigned char)suffix[i])) return 0;
    }
    return 1;
}

network_type_t router_detect_network(const char *host) {
    if (!host || !*host) return NET_CLEARNET;

    if (ends_with(host, ".onion")) return NET_TOR;
    if (ends_with(host, ".i2p"))   return NET_I2P;
    /* внутренние адреса Skhoron: либо алиас .skh, либо "сырой" Public-ID
       (в нашей схеме - hex-строка длиной ~60-68 символов) */
    if (ends_with(host, ".skh"))   return NET_SKHORON;
    {
        size_t len = strlen(host);
        int all_hex = (len >= 60 && len <= 68);
        for (size_t i = 0; all_hex && i < len; i++) {
            if (!isxdigit((unsigned char)host[i])) all_hex = 0;
        }
        if (all_hex) return NET_SKHORON;
    }

    return NET_CLEARNET;
}

const char *router_network_name(network_type_t net) {
    switch (net) {
        case NET_TOR:     return "TOR";
        case NET_I2P:     return "I2P";
        case NET_SKHORON: return "SKHORON";
        default:          return "CLEARNET";
    }
}

const char *router_error_string(router_error_t err) {
    switch (err) {
        case ROUTER_OK:                   return "OK";
        case ROUTER_ERR_NULL_ARG:         return "NULL_ARG";
        case ROUTER_ERR_EMPTY_AUTHORITY:  return "EMPTY_AUTHORITY";
        case ROUTER_ERR_TOO_LONG:         return "HOST_TOO_LONG";
        case ROUTER_ERR_BAD_IPV6_LITERAL: return "BAD_IPV6_LITERAL";
        case ROUTER_ERR_BAD_PORT:         return "BAD_PORT";
        default:                          return "UNKNOWN_ERROR";
    }
}

int router_default_port(scheme_type_t scheme) {
    switch (scheme) {
        case SCHEME_HTTP:  return 80;
        case SCHEME_HTTPS: return 443;
        default:           return 443; /* безопасный дефолт для неизвестных схем */
    }
}

static scheme_type_t parse_scheme(const char *url, size_t *scheme_end) {
    const char *sep = strstr(url, "://");
    if (!sep) { *scheme_end = 0; return SCHEME_UNKNOWN; }

    size_t slen = (size_t)(sep - url);
    *scheme_end = slen + 3;

    if (slen == 4 && strncasecmp(url, "http", 4) == 0) return SCHEME_HTTP;
    if (slen == 5 && strncasecmp(url, "https", 5) == 0) return SCHEME_HTTPS;
    return SCHEME_UNKNOWN;
}

/* Валидирует порт из строки: только цифры, диапазон 1..65535.
   Возвращает 0 при успехе, -1 при мусоре ("abc", "999999", "-1", ""). */
static int parse_port_strict(const char *s, int *out) {
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p)) return -1;

    long v = strtol(s, NULL, 10);
    if (v < 1 || v > 65535) return -1;
    *out = (int)v;
    return 0;
}

/* Разбирает authority-часть: либо "[ipv6]:port", "[ipv6]", либо "host:port", "host". */
static router_error_t parse_authority(const char *authority, target_t *out) {
    size_t alen = strlen(authority);
    if (alen == 0) return ROUTER_ERR_EMPTY_AUTHORITY;

    if (authority[0] == '[') {
        /* IPv6-литерал в скобках */
        const char *close = strchr(authority, ']');
        if (!close) return ROUTER_ERR_BAD_IPV6_LITERAL;

        size_t hostlen = (size_t)(close - authority - 1);
        if (hostlen == 0 || hostlen >= sizeof(out->host)) return ROUTER_ERR_BAD_IPV6_LITERAL;

        memcpy(out->host, authority + 1, hostlen);
        out->host[hostlen] = '\0';
        out->is_ipv6_literal = 1;

        const char *after = close + 1;
        if (*after == ':') {
            if (parse_port_strict(after + 1, &out->port) != 0) return ROUTER_ERR_BAD_PORT;
        } else if (*after == '\0') {
            out->port = -1;
        } else {
            return ROUTER_ERR_BAD_IPV6_LITERAL; /* мусор после "]" */
        }
        return ROUTER_OK;
    }

    /* Обычный host или host:port. strrchr(':') безопасен здесь, т.к. голые
       (без скобок) IPv6-литералы с несколькими ':' уже обработаны выше -
       если пользователь дал "::1:443" без скобок, это неоднозначно и мы
       требуем скобки (это стандартная практика в URL, RFC 3986). */
    if (strchr(authority, ':') != strrchr(authority, ':')) {
        /* больше одного ':' и нет скобок -> похоже на "голый" IPv6 без скобок */
        return ROUTER_ERR_BAD_IPV6_LITERAL;
    }

    char buf[300];
    if (alen >= sizeof(buf)) return ROUTER_ERR_TOO_LONG;
    memcpy(buf, authority, alen + 1);

    char *colon = strchr(buf, ':');
    if (colon) {
        *colon = '\0';
        if (parse_port_strict(colon + 1, &out->port) != 0) return ROUTER_ERR_BAD_PORT;
    } else {
        out->port = -1;
    }

    size_t hostlen = strlen(buf);
    if (hostlen == 0) return ROUTER_ERR_EMPTY_AUTHORITY;
    if (hostlen >= sizeof(out->host)) return ROUTER_ERR_TOO_LONG;

    memcpy(out->host, buf, hostlen + 1);
    out->is_ipv6_literal = 0;
    return ROUTER_OK;
}

router_error_t router_parse_url(const char *url, target_t *out) {
    if (!url || !out) return ROUTER_ERR_NULL_ARG;
    memset(out, 0, sizeof(*out));
    out->port = -1;

    size_t scheme_end;
    out->scheme = parse_scheme(url, &scheme_end);
    const char *p = url + scheme_end;

    const char *path = strchr(p, '/');
    /* но не путать закрывающую ']' IPv6-литерала с началом authority -
       если есть '[', ищем '/' только после соответствующей ']' */
    if (p[0] == '[') {
        const char *close = strchr(p, ']');
        if (close) path = strchr(close, '/');
    }

    size_t authority_len = path ? (size_t)(path - p) : strlen(p);
    if (authority_len == 0) return ROUTER_ERR_EMPTY_AUTHORITY;
    if (authority_len >= 300) return ROUTER_ERR_TOO_LONG;

    char authority[300];
    memcpy(authority, p, authority_len);
    authority[authority_len] = '\0';

    router_error_t err = parse_authority(authority, out);
    if (err != ROUTER_OK) return err;

    out->net = router_detect_network(out->host);
    return ROUTER_OK;
}
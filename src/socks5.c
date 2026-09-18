#define _POSIX_C_SOURCE 200809L
#include "socks5.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>

#define SOCKS5_CONNECT_TIMEOUT_SEC 10
#define SOCKS5_IO_TIMEOUT_SEC      15

/* --- connect() с таймаутом через неблокирующий сокет + select --- */
static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen,
                                 int timeout_sec, char *err, size_t errlen) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, addr, addrlen);
    if (rc == 0) {
        fcntl(fd, F_SETFL, flags); /* назад в блокирующий режим */
        return 0;
    }
    if (errno != EINPROGRESS) {
        snprintf(err, errlen, "connect() failed immediately: %s", strerror(errno));
        return -1;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };

    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc == 0) {
        snprintf(err, errlen, "connect timed out after %ds", timeout_sec);
        return -1;
    }
    if (rc < 0) {
        snprintf(err, errlen, "select() failed: %s", strerror(errno));
        return -1;
    }

    int so_err = 0;
    socklen_t so_err_len = sizeof(so_err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len);
    if (so_err != 0) {
        snprintf(err, errlen, "connect() failed: %s", strerror(so_err));
        return -1;
    }

    fcntl(fd, F_SETFL, flags); /* назад в блокирующий режим для read/write */
    return 0;
}

/* read()/write() не гарантируют, что весь буфер будет обработан за один
   вызов (особенно на реальной сети, не localhost) - поэтому используем
   эти обёртки везде вместо голых read()/write(). */
static int write_full(int fd, const void *buf, size_t len, char *err, size_t errlen) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errlen, "write() failed: %s", strerror(errno));
            return -1;
        }
        if (n == 0) { snprintf(err, errlen, "write() returned 0 (peer closed?)"); return -1; }
        sent += (size_t)n;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len, char *err, size_t errlen) {
    unsigned char *p = (unsigned char *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, p + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errlen, "read() failed: %s", strerror(errno));
            return -1;
        }
        if (n == 0) { snprintf(err, errlen, "connection closed by peer (got %zu/%zu bytes)", got, len); return -1; }
        got += (size_t)n;
    }
    return 0;
}

/* Подключается к локальному SOCKS5-прокси (proxy_host:proxy_port) и просит
   его сделать CONNECT к dst_host:dst_port. Реализует RFC 1928
   (без аутентификации - именно так по умолчанию слушают tor и i2pd). */
int socks5_connect(const char *proxy_host, int proxy_port,
                    const char *dst_host, int dst_port,
                    char *err, size_t errlen) {
    struct addrinfo hints, *res;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", proxy_port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    /* proxy обычно 127.0.0.1 / ::1 - но на случай другого хоста, всё равно
       не полагаемся на DNS через недоверенный резолвер: AI_NUMERICHOST
       заставит getaddrinfo не резолвить, а требовать IP-литерал напрямую,
       если вызывающий код передал IP. Если передано имя хоста - уберите
       этот флаг сознательно. Оставляем 0 для совместимости с "localhost". */
    if (getaddrinfo(proxy_host, portstr, &hints, &res) != 0) {
        snprintf(err, errlen, "getaddrinfo(%s) failed", proxy_host);
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        snprintf(err, errlen, "socket() failed: %s", strerror(errno));
        freeaddrinfo(res);
        return -1;
    }

    if (connect_with_timeout(fd, res->ai_addr, res->ai_addrlen,
                              SOCKS5_CONNECT_TIMEOUT_SEC, err, errlen) != 0) {
        char prefix[256];
        snprintf(prefix, sizeof(prefix), "connect to proxy %s:%d failed: %s",
                 proxy_host, proxy_port, err);
        strncpy(err, prefix, errlen - 1);
        err[errlen - 1] = '\0';
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    /* Таймауты на все дальнейшие read/write - если прокси зависнет
       посреди хендшейка, мы не зависнем вместе с ним. */
    struct timeval io_tv = { .tv_sec = SOCKS5_IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &io_tv, sizeof(io_tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &io_tv, sizeof(io_tv));

    /* --- SOCKS5 handshake: greeting, метод "без аутентификации" --- */
    unsigned char greet[3] = {0x05, 0x01, 0x00};
    if (write_full(fd, greet, sizeof(greet), err, errlen) != 0) { close(fd); return -1; }

    unsigned char method_reply[2];
    if (read_full(fd, method_reply, sizeof(method_reply), err, errlen) != 0) { close(fd); return -1; }
    if (method_reply[0] != 0x05 || method_reply[1] != 0x00) {
        snprintf(err, errlen, "proxy rejected auth method (ver=%d method=%d)",
                  method_reply[0], method_reply[1]);
        close(fd);
        return -1;
    }

    /* --- CONNECT-запрос с доменным именем (ATYP=0x03) ---
       Важно: домен передаём как есть прокси (Tor/i2pd сами резолвят) -
       мы никогда не делаем getaddrinfo(dst_host) сами, иначе для .onion/.i2p
       это была бы DNS-утечка через обычный резолвер. */
    unsigned char req[300];
    size_t hlen = strlen(dst_host);
    if (hlen > 255) { snprintf(err, errlen, "host too long (%zu bytes)", hlen); close(fd); return -1; }

    size_t i = 0;
    req[i++] = 0x05; req[i++] = 0x01; req[i++] = 0x00; /* VER, CMD=CONNECT, RSV */
    req[i++] = 0x03;                                    /* ATYP = domain name  */
    req[i++] = (unsigned char)hlen;
    memcpy(req + i, dst_host, hlen); i += hlen;
    req[i++] = (dst_port >> 8) & 0xFF;
    req[i++] = dst_port & 0xFF;

    if (write_full(fd, req, i, err, errlen) != 0) { close(fd); return -1; }

    /* --- Разбор ответа по RFC 1928, ПЕРЕМЕННОЙ длины ---
       VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(var) BND.PORT(2)
       BND.ADDR: 4 байта (IPv4), 16 байт (IPv6), или 1+N байт (домен). */
    unsigned char head[4];
    if (read_full(fd, head, sizeof(head), err, errlen) != 0) { close(fd); return -1; }

    if (head[0] != 0x05) {
        snprintf(err, errlen, "unexpected SOCKS version in reply: %d", head[0]);
        close(fd); return -1;
    }
    if (head[1] != 0x00) {
        static const char *rep_names[] = {
            "succeeded", "general failure", "not allowed by ruleset",
            "network unreachable", "host unreachable", "connection refused",
            "TTL expired", "command not supported", "address type not supported"
        };
        int rep = head[1];
        const char *name = (rep >= 0 && rep < 9) ? rep_names[rep] : "unknown";
        snprintf(err, errlen, "proxy refused CONNECT: %s (code=%d)", name, rep);
        close(fd);
        return -1;
    }

    size_t bnd_addr_len;
    switch (head[3]) {
        case 0x01: bnd_addr_len = 4;  break; /* IPv4 */
        case 0x04: bnd_addr_len = 16; break; /* IPv6 */
        case 0x03: {
            unsigned char domain_len;
            if (read_full(fd, &domain_len, 1, err, errlen) != 0) { close(fd); return -1; }
            bnd_addr_len = domain_len;
            break;
        }
        default:
            snprintf(err, errlen, "unknown ATYP in reply: %d", head[3]);
            close(fd);
            return -1;
    }

    unsigned char discard[256 + 2]; /* max domain(255) + port(2) на всякий случай */
    size_t remaining = bnd_addr_len + 2; /* + BND.PORT */
    if (remaining > sizeof(discard)) {
        snprintf(err, errlen, "BND.ADDR unexpectedly large (%zu bytes)", bnd_addr_len);
        close(fd);
        return -1;
    }
    if (read_full(fd, discard, remaining, err, errlen) != 0) { close(fd); return -1; }

    /* Возвращаем сокет в блокирующий режим для дальнейшего использования
       вызывающим кодом без сюрпризов (таймауты SO_RCVTIMEO/SNDTIMEO
       остаются - это не то же самое, что O_NONBLOCK). */
    return fd;
}
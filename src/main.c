#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "router.h"
#include "stream.h"

/* Явные коды возврата - чтобы вызывающие скрипты могли различать
   причину без парсинга stdout. */
#define EXIT_OK               0
#define EXIT_USAGE_ERROR      1
#define EXIT_PARSE_ERROR      2
#define EXIT_CONNECTION_ERROR 3

static void usage(const char *argv0) {
    fprintf(stderr,
        "Использование: %s [--live] <url1> [url2 ...]\n"
        "  --live   реально подключаться (по умолчанию dry-run, без сети)\n"
        "Примеры:\n"
        "  %s https://example.com\n"
        "  %s http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion\n"
        "  %s http://stats.i2p\n"
        "  %s \"https://[2001:db8::1]:8443\"\n",
        argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    int dry_run = 1;
    int first_url_idx = 1;
    int had_parse_error = 0;
    int had_connection_error = 0;

    if (argc < 2) { usage(argv[0]); return EXIT_USAGE_ERROR; }
    if (strcmp(argv[1], "--live") == 0) { dry_run = 0; first_url_idx = 2; }

    if (first_url_idx >= argc) { usage(argv[0]); return EXIT_USAGE_ERROR; }

    for (int i = first_url_idx; i < argc; i++) {
        target_t t;
        router_error_t perr = router_parse_url(argv[i], &t);
        if (perr != ROUTER_OK) {
            printf("[!] не удалось разобрать URL: %s (%s)\n",
                   argv[i], router_error_string(perr));
            had_parse_error = 1;
            continue;
        }
        if (t.port < 0) t.port = router_default_port(t.scheme);

        printf("URL:     %s\n", argv[i]);
        printf("  host:  %s%s%s\n", t.is_ipv6_literal ? "[" : "",
               t.host, t.is_ipv6_literal ? "]" : "");
        printf("  port:  %d\n", t.port);
        printf("  сеть:  %s\n", router_network_name(t.net));

        stream_result_t r = stream_open(&t, dry_run);
        if (r.ok) {
            if (r.transport == STREAM_TRANSPORT_TCP_FD)
                printf("  стрим: ОТКРЫТ (TCP), fd=%d\n", r.fd);
            else if (r.transport == STREAM_TRANSPORT_QUIC)
                printf("  стрим: ОТКРЫТ (QUIC), получено %zu байт\n", r.data_len);
            else
                printf("  стрим: %s\n", r.error);
        } else {
            printf("  ОШИБКА: %s\n", r.error);
            had_connection_error = 1;
        }
        /* Эта CLI-демонстрация больше ничего не делает с fd после печати
           статуса - закрываем его сами, иначе он утекает (в реальном
           коде-потребителе fd закрывает тот, кто дочитал стрим до конца). */
        if (r.transport == STREAM_TRANSPORT_TCP_FD && r.fd >= 0) close(r.fd);
        stream_result_free(&r);
        printf("\n");
    }

    if (had_connection_error) return EXIT_CONNECTION_ERROR;
    return had_parse_error ? EXIT_PARSE_ERROR : EXIT_OK;
}
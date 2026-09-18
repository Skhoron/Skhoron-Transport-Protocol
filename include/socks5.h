#ifndef SKHORON_SOCKS5_H
#define SKHORON_SOCKS5_H
#include <stddef.h>

/* Возвращает готовый fd подключённого TCP-сокета через SOCKS5-прокси,
   либо -1 при ошибке (текст ошибки пишется в err). */
int socks5_connect(const char *proxy_host, int proxy_port,
                    const char *dst_host, int dst_port,
                    char *err, size_t errlen);

#endif
#include <stdio.h>
#include <string.h>
#include "router.h"

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(cond, desc) do { \
    tests_run++; \
    if (!(cond)) { \
        tests_failed++; \
        printf("[FAIL] %s\n", desc); \
    } else { \
        printf("[ OK ] %s\n", desc); \
    } \
} while (0)

static void test_network_detection(void) {
    CHECK(router_detect_network("example.com") == NET_CLEARNET, "example.com -> CLEARNET");
    CHECK(router_detect_network("EXAMPLE.COM") == NET_CLEARNET, "case-insensitive host -> CLEARNET");
    CHECK(router_detect_network("something.onion") == NET_TOR, ".onion -> TOR");
    CHECK(router_detect_network("SOMETHING.ONION") == NET_TOR, ".ONION uppercase -> TOR");
    CHECK(router_detect_network("stats.i2p") == NET_I2P, ".i2p -> I2P");
    CHECK(router_detect_network("node.skh") == NET_SKHORON, ".skh -> SKHORON");
    CHECK(router_detect_network(
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2") == NET_SKHORON,
        "64-char hex Public-ID -> SKHORON");
    CHECK(router_detect_network("short") == NET_CLEARNET, "short non-hex host -> CLEARNET");
    CHECK(router_detect_network("") == NET_CLEARNET, "empty host -> CLEARNET (safe default)");
    CHECK(router_detect_network(NULL) == NET_CLEARNET, "NULL host -> CLEARNET (safe default, no crash)");
}

static void test_url_parsing_basic(void) {
    target_t t;
    router_error_t err = router_parse_url("https://example.com", &t);
    CHECK(err == ROUTER_OK, "parse https://example.com -> OK");
    CHECK(strcmp(t.host, "example.com") == 0, "host == example.com");
    CHECK(t.port == -1, "no explicit port -> -1 (caller applies default)");
    CHECK(t.scheme == SCHEME_HTTPS, "scheme == HTTPS");
    CHECK(router_default_port(t.scheme) == 443, "default port for https == 443");

    err = router_parse_url("http://example.com", &t);
    CHECK(err == ROUTER_OK, "parse http://example.com -> OK");
    CHECK(router_default_port(t.scheme) == 80, "default port for http == 80 (not 443)");

    err = router_parse_url("https://example.com:8443/some/path", &t);
    CHECK(err == ROUTER_OK, "parse with explicit port and path -> OK");
    CHECK(t.port == 8443, "explicit port parsed as 8443");
    CHECK(strcmp(t.host, "example.com") == 0, "host excludes path");
}

static void test_url_parsing_ipv6(void) {
    target_t t;
    router_error_t err = router_parse_url("https://[2001:db8::1]:8443/path", &t);
    CHECK(err == ROUTER_OK, "parse IPv6 literal with brackets+port -> OK");
    CHECK(strcmp(t.host, "2001:db8::1") == 0, "IPv6 host extracted without brackets");
    CHECK(t.port == 8443, "IPv6 port parsed correctly");
    CHECK(t.is_ipv6_literal == 1, "is_ipv6_literal flag set");

    err = router_parse_url("https://[::1]", &t);
    CHECK(err == ROUTER_OK, "parse bare IPv6 loopback without port -> OK");
    CHECK(t.port == -1, "no port -> -1");

    err = router_parse_url("https://2001:db8::1:443", &t);
    CHECK(err == ROUTER_ERR_BAD_IPV6_LITERAL, "unbracketed IPv6 with multiple ':' -> rejected, not silently mangled");
}

static void test_url_parsing_bad_input(void) {
    target_t t;
    CHECK(router_parse_url(NULL, &t) == ROUTER_ERR_NULL_ARG, "NULL url -> ROUTER_ERR_NULL_ARG");
    CHECK(router_parse_url("https://example.com", NULL) == ROUTER_ERR_NULL_ARG, "NULL out -> ROUTER_ERR_NULL_ARG");
    CHECK(router_parse_url("https://example.com:abc", &t) == ROUTER_ERR_BAD_PORT, "non-numeric port -> ROUTER_ERR_BAD_PORT (not silently 0)");
    CHECK(router_parse_url("https://example.com:999999", &t) == ROUTER_ERR_BAD_PORT, "out-of-range port -> ROUTER_ERR_BAD_PORT");
    CHECK(router_parse_url("https://example.com:0", &t) == ROUTER_ERR_BAD_PORT, "port 0 -> ROUTER_ERR_BAD_PORT");
    CHECK(router_parse_url("https://example.com:443abc", &t) == ROUTER_ERR_BAD_PORT, "trailing garbage in port -> ROUTER_ERR_BAD_PORT");
    CHECK(router_parse_url("https://", &t) == ROUTER_ERR_EMPTY_AUTHORITY, "empty authority -> ROUTER_ERR_EMPTY_AUTHORITY");
}

int main(void) {
    test_network_detection();
    test_url_parsing_basic();
    test_url_parsing_ipv6();
    test_url_parsing_bad_input();

    printf("\n%d/%d tests passed\n", tests_run - tests_failed, tests_run);
    return tests_failed == 0 ? 0 : 1;
}
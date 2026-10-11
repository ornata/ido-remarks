/* Pinned IDO 5.3 ugen node layout corroborated by translate/print_node_1.
 * No guest writes or calls from observers. Symbols are explicit analyst anchors. */
#include <errno.h>
static uint32_t ido_ugen_symbol;
static unsigned ido_ugen_event;

static void ido_ugen_scope(uint8_t *mem, uint32_t node) {
    unsigned guard = 0;
    for (; node && guard++ < 65536; node = MEM_U32(node + 8)) {
        if (MEM_U8(node + 32) == 33) {
            ido_ugen_symbol = MEM_U32(node + 36);
            break;
        }
    }
}

static int ido_ugen_begin(const char *kind) {
    const char *mode = getenv("IDO_REMARKS"), *symbol = getenv("IDO_UGEN_SYMBOL"),
               *name = getenv("IDO_REMARKS_FUNCTION");
    if (!mode || strcmp(mode, "json") || !symbol || !name || ido_ugen_symbol != strtoul(symbol, NULL, 10))
        return 0;
    fprintf(stderr, "{\"schema\":1,\"pass\":\"ido-ugen\",\"name\":\"%s\",\"function\":\"", kind);
    for (const char *p = name; *p; ++p) {
        if (*p == '"' || *p == '\\')
            fputc('\\', stderr);
        fputc(*p, stderr);
    }
    fprintf(stderr, "\",\"procedure_ordinal\":%u,\"event\":%u", ido_ugen_symbol, ++ido_ugen_event);
    return 1;
}

static void ido_ugen_node(uint8_t *mem, uint32_t node, const char *kind) {
    int saved_errno = errno;
    if (node && ido_ugen_begin(kind)) {
        fprintf(stderr,
                ",\"node_address\":%u,\"node_id\":%u,\"opcode\":%u,\"dtype\":%u,\"register\":%u,"
                "\"reference_count\":%u,\"visited\":%s,\"operand_addresses\":[%u,%u],\"i1\":%d}\n",
                node, MEM_U32(node + 16) >> 8, MEM_U8(node + 32), MEM_U8(node + 33) & 31, MEM_U8(node + 25) >> 1,
                MEM_U16(node + 20), MEM_U8(node + 25) & 1 ? "true" : "false", MEM_U32(node), MEM_U32(node + 4),
                MEM_S32(node + 36));
    }
    errno = saved_errno;
}

static uint32_t f_translate_tree(uint8_t *mem, uint32_t sp, uint32_t a0) {
    ido_ugen_scope(mem, a0);
    ido_ugen_node(mem, a0, "TranslateTreeBegin");
    uint32_t result = ido_original_translate_tree(mem, sp, a0);
    ido_ugen_node(mem, result, "TranslateTreeEnd");
    return result;
}

static uint32_t f_build_tree(uint8_t *mem, uint32_t sp, uint32_t a0) {
    ido_ugen_symbol = 0;
    uint32_t result = ido_original_build_tree(mem, sp, a0);
    ido_ugen_scope(mem, result);
    return result;
}

static void f_eval(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {
    ido_ugen_node(mem, a0, "EvaluationBegin");
    ido_original_eval(mem, sp, a0, a1);
    ido_ugen_node(mem, a0, "EvaluationEnd");
}

static uint32_t f_translate(uint8_t *mem, uint32_t sp, uint32_t a0) {
    ido_ugen_node(mem, a0, "TranslateBegin");
    uint32_t result = ido_original_translate(mem, sp, a0);
    ido_ugen_node(mem, result, "TranslateEnd");
    return result;
}

static void f_get_reg(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2) {
    ido_original_get_reg(mem, sp, a0, a1, a2);
    int saved_errno = errno;
    if (ido_ugen_begin("RegisterRequest"))
        fprintf(stderr, ",\"node_address\":%u,\"register\":%u,\"request_kind\":%u}\n", a1, a0 & 255, a2);
    errno = saved_errno;
}

static void f_fill_reg(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {
    ido_original_fill_reg(mem, sp, a0, a1, a2, a3);
    int saved_errno = errno;
    if (ido_ugen_begin("TemporaryAssigned"))
        fprintf(stderr, ",\"node_address\":%u,\"register\":%u,\"reference_count\":%u,\"request_kind\":%u}\n", a1,
                a0 & 255, a2, a3);
    errno = saved_errno;
}

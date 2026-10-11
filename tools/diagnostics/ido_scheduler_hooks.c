/* IDO 5.3 as1 scheduler observations, appended to static-recomp C.
 * Read-only host logging; generated return values and guest stack are preserved. */
#include <errno.h>
static unsigned ido_scheduler_block;
static uint32_t ido_scheduler_active;
static uint32_t ido_scheduler_symbol = 0xffffffffu;
static unsigned ido_scheduler_procedure;
static unsigned ido_scheduler_event;

static void ido_scheduler_string(const char *s) {
    fputc('"', stderr);
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            fputc('\\', stderr);
            fputc(c, stderr);
        } else if (c < 32 || c >= 127)
            fprintf(stderr, "\\u%04x", c);
        else
            fputc(c, stderr);
    }
    fputc('"', stderr);
}

static int ido_scheduler_begin(uint8_t *mem, const char *kind) {
    const char *mode = getenv("IDO_REMARKS");
    if (!mode || (strcmp(mode, "text") && strcmp(mode, "json")))
        return 0;
    uint32_t ptr = MEM_U32(0x10030814); /* currentent_name.f */
    if (!ptr || !ido_scheduler_active)
        return 0;
    char name[1025];
    unsigned i;
    for (i = 0; i < 1024; ++i) {
        name[i] = MEM_U8(ptr + i);
        if (!name[i])
            break;
    }
    if (i == 1024)
        return 0;
    const char *filter = getenv("IDO_REMARKS_FUNCTION");
    if (filter && *filter && strcmp(filter, name))
        return 0;
    ++ido_scheduler_event;
    if (!strcmp(mode, "json")) {
        fprintf(stderr, "{\"schema\":1,\"pass\":\"ido-scheduler\",\"name\":");
        ido_scheduler_string(kind);
        fprintf(stderr, ",\"function\":");
        ido_scheduler_string(name);
        fprintf(stderr,
                ",\"procedure_ordinal\":%u,\"procedure_symbol\":%u,\"event\":%u,\"block\":%u,\"block_address\":%u",
                ido_scheduler_procedure, ido_scheduler_symbol, ido_scheduler_event, ido_scheduler_block,
                ido_scheduler_active);
        return 2;
    }
    fprintf(stderr, "remark: %s: %s (block #%u)", name, kind, ido_scheduler_block);
    return 1;
}

static void ido_scheduler_end(int mode) {
    if (mode)
        fputs(mode == 2 ? "}\n" : " [-Rpass-analysis=ido-scheduler]\n", stderr);
}

static void ido_scheduler_node(uint8_t *mem, const char *key, uint32_t node) {
    fprintf(stderr,
            ",\"%s\":{\"address\":%u,\"word\":\"%08x\",\"input_index\":%u,"
            "\"flags\":%u,\"dependency_count\":%u,\"priority_height\":%u,\"ready_cycle\":%u,\"source_line\":%u,"
            "\"instruction_order\":%d}",
            key, node, MEM_U32(node), MEM_U32(node + 0x14), MEM_U32(node + 0x20), MEM_U16(node + 0x2a),
            MEM_U16(node + 0x2c), MEM_U16(node + 0x2e), MEM_U32(node + 48), MEM_S32(node + 12));
}

/* Native comparator's final integer scores include a pool-slot order term. */
static void ido_scheduler_score(uint8_t *mem, uint32_t candidate, uint32_t incumbent, uint32_t candidate_score,
                                uint32_t incumbent_score) {
    int saved_errno = errno;
    int mode = ido_scheduler_begin(mem, "SchedulerScore");
    if (mode) {
        int32_t cindex = (int32_t)(candidate - 0x10026390u) / 56;
        int32_t iindex = (int32_t)(incumbent - 0x10026390u) / 56;
        uint32_t cbase = candidate_score - (uint32_t)cindex, ibase = incumbent_score - (uint32_t)iindex;
        ido_scheduler_node(mem, "candidate", candidate);
        ido_scheduler_node(mem, "incumbent", incumbent);
        fprintf(
            stderr,
            ",\"candidate_score\":%d,\"incumbent_score\":%d,\"candidate_slot_index\":%d,\"incumbent_slot_index\":%d,"
            "\"candidate_without_slot\":%d,\"incumbent_without_slot\":%d,\"base_scores_equal\":%s,\"slot_decides\":%s",
            (int32_t)candidate_score, (int32_t)incumbent_score, cindex, iindex, (int32_t)cbase, (int32_t)ibase,
            cbase == ibase ? "true" : "false", cbase == ibase && cindex != iindex ? "true" : "false");
    }
    ido_scheduler_end(mode);
    errno = saved_errno;
}

/* Observe the default selector's actual lexicographic gates at L4342dc. */
static void ido_ready_comparison(uint8_t *mem, uint32_t candidate, uint32_t incumbent, uint32_t cstart, uint32_t istart,
                                 uint32_t cheight, uint32_t iheight, uint32_t ccontext, uint32_t icontext) {
    int saved_errno = errno;
    if (!incumbent)
        return;
    int mode = ido_scheduler_begin(mem, "ReadyComparison");
    if (mode) {
        uint32_t cline = MEM_U32(candidate + 48), iline = MEM_U32(incumbent + 48);
        int32_t corder = MEM_S32(candidate + 12), iorder = MEM_S32(incumbent + 12);
        int weighted = MEM_U32(0x10023634) != 0, preferred = 0, known = 1;
        const char *key;
        if (cstart != istart) {
            key = "start_cycle";
            preferred = cstart < istart;
        } else if (weighted) {
            key = "weighted_score";
            known = 0;
        } else if (cheight != iheight) {
            key = "priority_height";
            preferred = cheight > iheight;
        } else if (ccontext != icontext) {
            key = "dependency_context";
            preferred = ccontext > icontext;
        } else if (cline != iline) {
            key = "source_line";
            preferred = cline < iline;
        } else if (corder != iorder) {
            key = "instruction_order";
            preferred = corder < iorder;
        } else {
            key = "keep_incumbent";
        }
        ido_scheduler_node(mem, "candidate", candidate);
        ido_scheduler_node(mem, "incumbent", incumbent);
        fprintf(stderr,
                ",\"candidate_start\":%u,\"incumbent_start\":%u,\"candidate_height\":%u,\"incumbent_height\":%u,"
                "\"candidate_context\":%u,\"incumbent_context\":%u,\"source_lines_equal\":%s,\"deciding_key\":\"%s\","
                "\"candidate_preferred\":%s",
                cstart, istart, cheight, iheight, ccontext, icontext, cline == iline ? "true" : "false", key,
                !known      ? "null"
                : preferred ? "true"
                            : "false");
    }
    ido_scheduler_end(mode);
    errno = saved_errno;
}

static uint32_t f_reorganize_bb(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {
    int saved_errno = errno;
    uint32_t previous = ido_scheduler_active;
    ido_scheduler_active = a0;
    uint32_t symbol = MEM_U32(0x10030810);
    if (symbol != ido_scheduler_symbol) {
        ido_scheduler_symbol = symbol;
        ++ido_scheduler_procedure;
        ido_scheduler_block = 0;
    }
    ++ido_scheduler_block;
    int mode = ido_scheduler_begin(mem, "BlockStart");
    if (mode)
        fprintf(stderr, ",\"reschedule\":%s,\"input_instruction_count\":%u", a1 ? "true" : "false", MEM_U16(a0 + 0x3c));
    ido_scheduler_end(mode);
    errno = saved_errno;
    uint32_t result = ido_original_reorganize_bb(mem, sp, a0, a1);
    saved_errno = errno;
    mode = ido_scheduler_begin(mem, "BlockEnd");
    if (mode)
        fprintf(stderr, ",\"returned_cycles\":%u", result);
    ido_scheduler_end(mode);
    ido_scheduler_active = previous;
    errno = saved_errno;
    return result;
}

static uint32_t f_start_time(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {
    uint32_t ready = MEM_U16(a1 + 0x2e);
    uint32_t result = ido_original_start_time(mem, sp, a0, a1, a2, a3);
    int saved_errno = errno;
    int mode = ido_scheduler_begin(mem, "StartTime");
    if (mode) {
        ido_scheduler_node(mem, "node", a1);
        fprintf(stderr,
                ",\"requested_cycle\":%u,\"dependency_ready_cycle\":%u,\"returned_cycle\":%u,"
                "\"resource_delay\":%u",
                a0, ready, result, result > (a0 > ready ? a0 : ready) ? result - (a0 > ready ? a0 : ready) : 0);
    }
    ido_scheduler_end(mode);
    errno = saved_errno;
    return result;
}

/* The generated ABI returns a register even though the guest routine is void. */
static uint32_t f_start_instruction(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {
    uint32_t result = ido_original_start_instruction(mem, sp, a0, a1, a2, a3);
    int saved_errno = errno;
    int mode = ido_scheduler_begin(mem, "InstructionIssue");
    if (mode)
        fprintf(stderr, ",\"cycle\":%u,\"word\":\"%08x\"", a0, a1);
    ido_scheduler_end(mode);
    errno = saved_errno;
    return result;
}

static uint32_t f_is_node_better(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {
    uint32_t weight0 = MEM_U32(sp + 16), weight1 = MEM_U32(sp + 20);
    uint32_t result = ido_original_is_node_better(mem, sp, a0, a1, a2, a3);
    int saved_errno = errno;
    int mode = ido_scheduler_begin(mem, "PriorityComparison");
    if (mode) {
        ido_scheduler_node(mem, "candidate", a0);
        ido_scheduler_node(mem, "incumbent", a1);
        fprintf(stderr,
                ",\"candidate_preferred\":%s,\"candidate_weight\":%u,\"incumbent_weight\":%u,"
                "\"candidate_context\":%u,\"incumbent_context\":%u",
                result ? "true" : "false", weight0, weight1, a2, a3);
    }
    ido_scheduler_end(mode);
    errno = saved_errno;
    return result;
}

static uint32_t func_42d698(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2,
                            uint32_t a3) {
    uint32_t result = ido_original_dependency(mem, sp, v0, a0, a1, a2, a3);
    int saved_errno = errno;
    int mode = ido_scheduler_begin(mem, "DependencyRequest");
    if (mode) {
        ido_scheduler_node(mem, "from", a0);
        ido_scheduler_node(mem, "to", a1);
        fprintf(stderr, ",\"requested_latency\":%d,\"requested_flags\":%u", (int32_t)a2, a3);
    }
    ido_scheduler_end(mode);
    errno = saved_errno;
    return result;
}

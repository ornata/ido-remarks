/* Named boundaries for the shipped -xbbdbg stream. No guessed CFG offsets. */
static unsigned ido_xbb_depth;
static unsigned ido_xbb_sequence;

static int ido_xbb_event_begin(uint8_t *mem, const char *kind) {
    if (!getenv("IDO_XBB_CAPTURE") || !ido_xbb_depth)
        return 0;
    uint32_t ptr = MEM_U32(0x10030814);
    if (!ptr)
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
    const char *filter = getenv("IDO_XBB_FUNCTION");
    if (filter && strcmp(filter, name))
        return 0;
    wrapper_fflush(mem, 0);
    fflush(stdout);
    fputs("\n{\"schema\":1,\"pass\":\"ido-xbb\",\"name\":", stderr);
    ido_scheduler_string(kind);
    fputs(",\"function\":", stderr);
    ido_scheduler_string(name);
    fprintf(stderr, ",\"procedure_ordinal\":%u,\"event\":%u", MEM_U32(0x10030810), ++ido_xbb_sequence);
    return 1;
}

static void ido_xbb_list(uint8_t *mem, uint32_t link) {
    unsigned count = 0;
    fputc('[', stderr);
    for (; link && count < 4096; link = MEM_U32(link + 4), ++count) {
        if (count)
            fputc(',', stderr);
        fprintf(stderr, "%u", MEM_U32(MEM_U32(link) + 64));
    }
    fputc(']', stderr);
    if (link)
        fputs(",\"truncated\":true", stderr);
}

/* BB offsets corroborated by xbb's own table, predecessor and instruction loops. */
static void ido_xbb_snapshot(uint8_t *mem, const char *phase) {
    int saved_errno = errno;
    if (!getenv("IDO_XBB_CAPTURE") || !ido_xbb_depth)
        return;
    uint32_t count = MEM_U32(0x100232fc), table = MEM_U32(0x100235d4);
    if (count > 4096 || !table) {
        errno = saved_errno;
        return;
    }
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t block = MEM_U32(table + 4 * i);
        if (!block || !ido_xbb_event_begin(mem, "CFGSnapshot"))
            continue;
        unsigned size = MEM_U16(block + 60);
        fprintf(stderr,
                ",\"phase\":\"%s\",\"block\":%u,\"block_address\":%u,\"weight\":%u,\"flags\":%u,\"instruction_count\":%"
                "u,\"predecessors\":",
                phase, MEM_U32(block + 64), block, MEM_U16(block + 72), MEM_U32(block + 68), size);
        ido_xbb_list(mem, MEM_U32(block + 20));
        fputs(",\"successors\":", stderr);
        ido_xbb_list(mem, MEM_U32(block + 16));
        fputs(",\"instructions\":[", stderr);
        uint32_t instructions = MEM_U32(block + 12);
        for (unsigned j = 1; j <= size && j <= 4096; ++j) {
            if (j > 1)
                fputc(',', stderr);
            uint32_t instruction = instructions + 40 * j;
            fprintf(stderr, "{\"index\":%u,\"word\":\"%08x\",\"flag33\":%u,\"flag34\":%u}", j, MEM_U32(instruction),
                    MEM_U8(instruction + 33), MEM_U8(instruction + 34));
        }
        fprintf(stderr, "],\"is_root\":%s", MEM_U32(block + 20) ? "false" : "true");
        if (size > 4096)
            fputs(",\"truncated\":true", stderr);
        fputs("}\n", stderr);
    }
    errno = saved_errno;
}

static int ido_xbb_member(uint8_t *mem, uint32_t table, uint32_t row, uint32_t bit) {
    uint32_t ptr = MEM_U32(table);
    if (!ptr)
        return 0;
    ptr = MEM_U32(ptr + row * 4);
    return ptr && (MEM_U32(ptr + (bit / 32) * 4) & (1u << (bit % 32)));
}

static void ido_xbb_block_check(uint8_t *mem, uint32_t source, uint32_t target) {
    int saved_errno = errno;
    if (ido_xbb_event_begin(mem, "XbbBlockCandidate")) {
        unsigned src = MEM_U32(source + 64), dst = MEM_U32(target + 64);
        int difference = (int)MEM_U16(source + 72) - (int)MEM_U16(target + 72);
        unsigned limit = 3 * MEM_U32(0x100003f0) + 3;
        fprintf(stderr,
                ",\"source_block\":%u,\"target_block\":%u,\"source_flags\":%u,\"weight_difference\":%d,\"weight_"
                "limit\":%u,\"weight_passes\":%s,"
                "\"target_in_source_dominators\":%s,\"target_in_source_postdominators\":%s}\n",
                src, dst, MEM_U32(source + 68), difference, limit, difference < (int)limit ? "true" : "false",
                ido_xbb_member(mem, 0x100235d8, src, dst) ? "true" : "false",
                ido_xbb_member(mem, 0x100235dc, src, dst) ? "true" : "false");
    }
    errno = saved_errno;
}

static void ido_xbb_instruction_reject(uint8_t *mem, uint32_t source, uint32_t target, uint32_t index, uint32_t word,
                                       const char *reason) {
    int saved_errno = errno;
    if (ido_xbb_event_begin(mem, index ? "XbbInstructionRejected" : "XbbBlockRejected"))
        fprintf(stderr,
                ",\"source_block\":%u,\"target_block\":%u,\"instruction\":%u,\"word\":\"%08x\",\"reason\":\"%s\"}\n",
                MEM_U32(source + 64), MEM_U32(target + 64), index, word, reason);
    errno = saved_errno;
}

static void func_4287c8(uint8_t *mem, uint32_t sp, uint32_t a0) {
    ido_original_xbb_sets(mem, sp, a0);
    ido_xbb_snapshot(mem, "after_4287c8");
}
static void func_428fc4(uint8_t *mem, uint32_t sp, uint32_t a0) {
    ido_original_xbb_weights(mem, sp, a0);
    ido_xbb_snapshot(mem, "after_428fc4");
}
static void func_428a2c(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {
    ido_original_xbb_dominators(mem, sp, a0, a1);
    ido_xbb_snapshot(mem, "after_428a2c");
}
static void func_429534(uint8_t *mem, uint32_t sp) {
    ido_original_xbb_postdominators(mem, sp);
    ido_xbb_snapshot(mem, "after_429534");
}
static void func_42aa0c(uint8_t *mem, uint32_t sp) {
    ido_original_xbb_moves(mem, sp);
    ido_xbb_snapshot(mem, "after_moves");
}
static void func_42b51c(uint8_t *mem, uint32_t sp) {
    ido_original_xbb_cleanup(mem, sp);
    ido_xbb_snapshot(mem, "after_cleanup");
}

static uint32_t func_42a028(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {
    uint32_t flags = MEM_U32(a0 + 68), opcode = MEM_U16(a1 + 78);
    uint32_t result = ido_original_xbb_proposal(mem, sp, a0, a1, a2, a3);
    int saved_errno = errno;
    if (ido_xbb_event_begin(mem, "XbbProposalResult"))
        fprintf(stderr,
                ",\"source_block\":%u,\"target_block\":%u,\"accepted\":%s,\"instruction\":%u,\"reason\":\"%s\"}\n",
                MEM_U32(a0 + 64), MEM_U32(a1 + 64), result ? "true" : "false", result,
                result              ? "selected"
                : !(flags & 0x2000) ? "source_flag_0x2000_clear"
                : opcode >= 0x123   ? "target_opcode_limit"
                                    : "no_candidate_or_unlogged_predicate");
    errno = saved_errno;
    return result;
}

static uint32_t f_reschedule(uint8_t *mem, uint32_t sp, uint32_t a0) {
    ido_xbb_snapshot(mem, "before_reschedule");
    uint32_t result = ido_original_xbb_reschedule(mem, sp, a0);
    ido_xbb_snapshot(mem, "after_reschedule");
    return result;
}
static void ido_xbb_scope(uint8_t *mem, const char *kind) {
    if (!getenv("IDO_XBB_CAPTURE"))
        return;
    /* Flush the runtime's IRIX stdio buffers, not just host stdout. This changes
     * IO buffering only; the diagnostic runner still verifies object transparency. */
    wrapper_fflush(mem, 0);
    fflush(stdout);
    uint32_t ptr = MEM_U32(0x10030814);
    if (!ptr)
        return;
    char name[1025];
    unsigned i;
    for (i = 0; i < 1024; ++i) {
        name[i] = MEM_U8(ptr + i);
        if (!name[i])
            break;
    }
    if (i == 1024)
        return;
    fprintf(stderr, "{\"schema\":1,\"pass\":\"ido-xbb\",\"name\":");
    ido_scheduler_string(kind);
    fprintf(stderr, ",\"function\":");
    ido_scheduler_string(name);
    fputs("}\n", stderr);
    fflush(stderr);
}

static void f_do_xbb_opt(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {
    int saved_errno = errno;
    ido_xbb_scope(mem, "Begin");
    ++ido_xbb_depth;
    errno = saved_errno;
    ido_original_xbb(mem, sp, a0, a1);
    saved_errno = errno;
    ido_xbb_scope(mem, "End");
    --ido_xbb_depth;
    errno = saved_errno;
}

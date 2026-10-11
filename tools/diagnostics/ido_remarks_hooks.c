/* Appended to the pinned IDO 5.3 static-recomp uopt.c by patch_ido_remarks.py.
 * Read-only guest observations; no floating arithmetic or guest calls.
 * Addresses/layouts are version-specific and recorded in IDO_REMARKS.md. */
#include <errno.h>
static unsigned ido_remark_procedure;
static unsigned ido_remark_event;
static unsigned ido_generated_narrowing;
#ifdef IDO_DEFINITION_TRACES
static unsigned ido_definition_file;
static unsigned ido_definition_line;
static void ido_definition_input(uint8_t *mem);
#endif

static void ido_json_string(const char *s) {
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

static int ido_remark_mode(uint8_t *mem, char name[1025]) {
    const char *mode = getenv("IDO_REMARKS");
    if (!mode || (strcmp(mode, "text") && strcmp(mode, "json")))
        return 0;
    uint32_t len = MEM_U32(0x1001c8d0); /* entnam0len */
    if (len > 1024)
        return 0;
    for (uint32_t i = 0; i < len; ++i)
        name[i] = MEM_U8(0x1001c4d0 + i);
    name[len] = 0;
    const char *filter = getenv("IDO_REMARKS_FUNCTION");
    if (filter && *filter && strcmp(filter, name))
        return 0;
    return !strcmp(mode, "json") ? 2 : 1;
}

static void ido_begin_pass(int mode, const char *name, const char *kind, const char *pass) {
    ++ido_remark_event;
    if (mode == 2) {
        fprintf(stderr, "{\"schema\":1,\"pass\":");
        ido_json_string(pass);
        fprintf(stderr, ",\"name\":");
        ido_json_string(kind);
        fprintf(stderr, ",\"function\":");
        ido_json_string(name);
        fprintf(stderr, ",\"procedure_ordinal\":%u,\"event\":%u", ido_remark_procedure, ido_remark_event);
    } else
        fprintf(stderr, "remark: %s: %s (procedure #%u, event %u)", name, kind, ido_remark_procedure, ido_remark_event);
}

static void ido_begin(int mode, const char *name, const char *kind) {
    ido_begin_pass(mode, name, kind, "ido-regalloc");
}

static void ido_cse_end(int mode) {
    fputs(mode == 2 ? "}\n" : " [-Rpass-analysis=ido-cse]\n", stderr);
}

static void ido_end(int mode) {
    fputs(mode == 2 ? "}\n" : " [-Rpass-analysis=ido-regalloc]\n", stderr);
}

static void ido_allocation_remark(uint8_t *mem, uint32_t lr, const char *kind) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (!mode) {
        errno = saved_errno;
        return;
    }
    uint32_t chain = MEM_U32(lr);
    unsigned benefit_status = MEM_U8(lr + 0x23);
    ido_begin(mode, name, kind);
    if (mode == 2) {
        fprintf(stderr,
                ",\"range\":%u,\"eligible\":%s,\"benefit_status\":%u,\"savings_f32_bits\":\"%08x\","
                "\"internal_color\":%d,\"interferences\":%u,\"colors_left\":%u,"
                "\"forbidden_words\":[\"%08x\",\"%08x\"],\"priority_divisor\":%u,"
                "\"expression\":{\"table\":%u,\"chain\":%u,\"bit\":%u,\"type\":%u,\"dtype\":%u}",
                MEM_U32(lr + 4),
                benefit_status == 1   ? "true"
                : benefit_status == 2 ? "false"
                                      : "null",
                benefit_status, MEM_U32(lr + 0x30), MEM_S8(lr + 0x20), MEM_U32(lr + 0x24), MEM_U8(lr + 0x21),
                MEM_U32(lr + 0x28), MEM_U32(lr + 0x2c), MEM_U32(lr + 0x1c), MEM_U16(chain + 4), MEM_U16(chain + 6),
                MEM_U16(chain + 2), MEM_U8(chain), MEM_U8(chain + 1));
    } else {
        fprintf(stderr,
                ": range=%u expression={%u|%u} type=%u color=%d "
                "benefit-status=%u savings-f32=0x%08x interferences=%u colors-left=%u forbidden=%08x:%08x",
                MEM_U32(lr + 4), MEM_U16(chain + 4), MEM_U16(chain + 6), MEM_U8(chain), MEM_S8(lr + 0x20),
                benefit_status, MEM_U32(lr + 0x30), MEM_U32(lr + 0x24), MEM_U8(lr + 0x21), MEM_U32(lr + 0x28),
                MEM_U32(lr + 0x2c));
    }
    ido_end(mode);
    errno = saved_errno;
}

static int ido_member(uint8_t *mem, uint32_t bv, uint32_t bit) {
    uint32_t data = MEM_U32(bv + 4);
    return data && (MEM_U32(data + (bit / 32) * 4) & (0x80000000u >> (bit % 32)));
}

static void ido_color_snapshot(uint8_t *mem) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (!mode || MEM_U8(0x1001eb84)) {
        errno = saved_errno;
        return;
    }
    uint32_t count = MEM_U32(0x1001cb3c); /* oldbitposcount: same domain as printregs */
    uint32_t table = MEM_U32(0x1001cc30);
    for (uint32_t i = 0; i < count; ++i) {
        if (!ido_member(mem, 0x1001cc00, i) && i != MEM_U32(0x1001cb48) && i != MEM_U32(0x1001cb4c) &&
            i != MEM_U32(0x1001cb50))
            continue;
        for (uint32_t lr = MEM_U32(table + 8 * i + 4); lr; lr = MEM_U32(lr + 0x34)) {
            ido_allocation_remark(mem, lr, "RangeColor");
            for (uint32_t lu = MEM_U32(lr + 8); lu; lu = MEM_U32(lu + 4)) {
                uint32_t block = MEM_U32(lu);
                ido_begin(mode, name, "LiveUnit");
                if (mode == 2)
                    fprintf(stderr,
                            ",\"range\":%u,\"block\":%u,\"frequency\":%u,"
                            "\"loads\":%u,\"stores\":%u,\"internal_register\":%u,"
                            "\"reload\":%s,\"save\":%s,\"dead_out\":%s,\"first_store\":%s",
                            MEM_U32(lr + 4), MEM_U16(block + 8), MEM_U32(block + 0x2c), MEM_U16(lu + 0x10),
                            MEM_U8(lu + 0x12), MEM_U8(lu + 0x13), MEM_U8(lu + 0x15) ? "true" : "false",
                            MEM_U8(lu + 0x16) ? "true" : "false", MEM_U8(lu + 0x17) ? "true" : "false",
                            MEM_U8(lu + 0x14) ? "true" : "false");
                else
                    fprintf(stderr, ": range=%u block=%u loads=%u stores=%u reload=%u save=%u", MEM_U32(lr + 4),
                            MEM_U16(block + 8), MEM_U16(lu + 0x10), MEM_U8(lu + 0x12), MEM_U8(lu + 0x15),
                            MEM_U8(lu + 0x16));
                ido_end(mode);
            }
        }
    }
    errno = saved_errno;
}

static void ido_slot_snapshot(uint8_t *mem) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (!mode || MEM_U8(0x1001eb84)) {
        errno = saved_errno;
        return;
    }
    uint32_t count = MEM_U32(0x1001cb40), table = MEM_U32(0x1001cc30);
    for (uint32_t i = 0; i < count; ++i) {
        if (!ido_member(mem, 0x1001cbe0, i))
            continue;
        uint32_t chain = MEM_U32(table + 8 * i), type = MEM_U8(chain);
        if (type != 4 && type != 5 && type != 6)
            continue;
        uint32_t slot = MEM_U32(chain + (type == 5 ? 0x24 : 0x20));
        if (!slot)
            continue;
        ido_begin(mode, name, "SpillSlot");
        if (mode == 2)
            fprintf(stderr,
                    ",\"expression\":{\"table\":%u,\"chain\":%u,\"bit\":%u},"
                    "\"slot\":%u,\"m_offset\":%d,\"size\":%u",
                    MEM_U16(chain + 4), MEM_U16(chain + 6), MEM_U16(chain + 2), MEM_U32(slot), MEM_S32(slot + 4),
                    MEM_U32(slot + 8));
        else
            fprintf(stderr, ": expression={%u|%u} slot=%u M-offset=%d size=%u", MEM_U16(chain + 4), MEM_U16(chain + 6),
                    MEM_U32(slot), MEM_S32(slot + 4), MEM_U32(slot + 8));
        ido_end(mode);
    }
    errno = saved_errno;
}

static void f_oneproc(uint8_t *mem, uint32_t sp) {
    ++ido_remark_procedure;
#ifdef IDO_DEFINITION_TRACES
    ido_definition_file = ido_definition_line = 0;
#endif
    ido_original_oneproc(mem, sp);
}

/* add_cvtl's generated ABI carries the Graphnode in incoming v0. */
static uint32_t func_415f9c(uint8_t *mem, uint32_t sp, uint32_t v0, uint32_t a0, uint32_t a1, uint32_t a2) {
    unsigned type = MEM_U8(a0), dtype = MEM_U8(a0 + 1);
    unsigned width = type == 3 || type == 6                                          ? MEM_U8(a0 + 32) * 8
                     : type == 4 && MEM_U8(a0 + 32) == 25                            ? MEM_U32(a0 + 44)
                     : type == 4 && (MEM_U8(a0 + 32) == 51 || MEM_U8(a0 + 32) == 54) ? MEM_U16(a0 + 60) * 8
                                                                                     : 0;
    uint32_t result = ido_original_add_cvtl(mem, sp, v0, a0, a1, a2);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && result) {
        ido_begin_pass(mode, name, "ConversionDecision", "ido-cse");
        fprintf(stderr,
                ",\"operand_address\":%u,\"result_address\":%u,\"source_type\":%u,\"source_dtype\":%u,"
                "\"destination_dtype\":%u,\"requested_bits\":%u,\"operand_width_bits\":%u,"
                "\"block\":%u,\"same_operand\":%s,\"result_type\":%u,\"result_opcode\":%u",
                a0, result, type, dtype, a2, a1, width, v0 ? MEM_U16(v0 + 8) : 0, result == a0 ? "true" : "false",
                MEM_U8(result), MEM_U8(result) == 4 ? MEM_U8(result + 32) : 255);
        ido_cse_end(mode);
    }
    errno = saved_errno;
    return result;
}

static void f_gen_cvtl(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {
    ido_original_gen_cvtl(mem, sp, a0, a1);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        ido_begin_pass(mode, name, "ConversionEmitted", "ido-cse");
        fprintf(stderr, ",\"requested_bits\":%u,\"destination_dtype\":%u,\"block_id\":%u", a0 * 8, a1,
                MEM_U32(0x1001c4c4));
        ido_cse_end(mode);
    }
    errno = saved_errno;
}

static void f_createcvtl(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {
    unsigned previous = ido_generated_narrowing;
    ido_generated_narrowing = 1;
    ido_original_createcvtl(mem, sp, a0, a1);
    ido_generated_narrowing = previous;
}

static void f_readnxtinst(uint8_t *mem, uint32_t sp) {
    int saved_errno = errno;
    unsigned opcode = MEM_U8(0x10011ff0);
#ifdef IDO_DEFINITION_TRACES
    if (opcode == 81) {
        ido_definition_file = MEM_U16(0x10011ff2);
        ido_definition_line = MEM_U32(0x10011ff4);
    }
    if (opcode == 123)
        ido_definition_input(mem);
#endif
    if (opcode == 24 || opcode == 25) {
        char name[1025];
        int mode = ido_remark_mode(mem, name);
        if (mode) {
            ido_begin_pass(mode, name, "ConversionInput", "ido-cse");
            fprintf(stderr,
                    ",\"opcode\":%u,\"destination_dtype\":%u,\"requested_bits\":%u,\"generated_local_narrowing\":%s",
                    opcode, MEM_U8(0x10011ff1) & 31, opcode == 25 ? MEM_U32(0x10011ff4) : 0,
                    ido_generated_narrowing ? "true" : "false");
            ido_cse_end(mode);
        }
    }
    errno = saved_errno;
    ido_original_readnxtinst(mem, sp);
}

static void f_codemotion(uint8_t *mem, uint32_t sp) {
    ido_original_codemotion(mem, sp);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && !MEM_U8(0x1001eb84)) {
        uint32_t table = MEM_U32(0x1001cc30), count = MEM_U32(0x1001cb3c);
        unsigned guard = 0;
        for (uint32_t block = MEM_U32(0x1001c8f8); block && guard++ < 65536; block = MEM_U32(block + 12)) {
            for (uint32_t bit = 0; bit < count; ++bit) {
                int insert = ido_member(mem, block + 0x164, bit), del = ido_member(mem, block + 0x124, bit);
                if (!insert && !del)
                    continue;
                uint32_t chain = MEM_U32(table + bit * 8);
                if (!chain)
                    continue;
                ido_begin_pass(mode, name, "PREPlan", "ido-cse");
                fprintf(stderr,
                        ",\"expression\":{\"table\":%u,\"chain\":%u,\"bit\":%u},\"expression_type\":%u,"
                        "\"dtype\":%u,\"opcode\":%u,\"block\":%u,\"planned_insert\":%s,\"planned_delete\":%s",
                        MEM_U16(chain + 4), MEM_U16(chain + 6), bit, MEM_U8(chain), MEM_U8(chain + 1),
                        MEM_U8(chain) == 4 ? MEM_U8(chain + 16) : 255, MEM_U16(block + 8), insert ? "true" : "false",
                        del ? "true" : "false");
                ido_cse_end(mode);
            }
        }
    }
    errno = saved_errno;
}
static void f_compute_save(uint8_t *mem, uint32_t sp, uint32_t a0) {
    ido_allocation_remark(mem, a0, "BenefitBefore");
    ido_original_compute_save(mem, sp, a0);
    ido_allocation_remark(mem, a0, "AllocationBenefit");
}

/* The generating guest instructions corroborate regsused at node+44+class*8.
 * These are block contributors, not inferred original C identities. */
static void f_updateforbidden(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {
    uint32_t before0 = MEM_U32(a2 + 40), before1 = MEM_U32(a2 + 44);
    ido_original_updateforbidden(mem, sp, a0, a1, a2, a3);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        ido_begin(mode, name, "ForbiddenContribution");
        fprintf(stderr,
                ",\"range\":%u,\"block\":%u,\"regclass\":%u,\"except_register\":%u,"
                "\"before\":[\"%08x\",\"%08x\"],\"after\":[\"%08x\",\"%08x\"],"
                "\"block_regsused\":[\"%08x\",\"%08x\"]",
                MEM_U32(a2 + 4), MEM_U16(a0 + 8), a3, a1, before0, before1, MEM_U32(a2 + 40), MEM_U32(a2 + 44),
                MEM_U32(a0 + 44 + a3 * 8), MEM_U32(a0 + 48 + a3 * 8));
        ido_end(mode);
    }
    errno = saved_errno;
}

static void ido_adjacency(uint8_t *mem, uint32_t parent, uint32_t piece, uint32_t block, uint32_t shared,
                          uint32_t previous) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        unsigned left = MEM_U8(piece + 33), degree = MEM_U32(piece + 36), heuristic = MEM_U8(0x1001eb10);
        int accepted = heuristic ? shared < previous && left * 2 >= degree + shared : left != 0;
        ido_begin(mode, name, "SplitAdjacency");
        fprintf(stderr,
                ",\"parent_range\":%u,\"range\":%u,\"block\":%u,\"shared\":%u,"
                "\"previous_colors_left\":%u,\"colors_left\":%u,\"interferences\":%u,"
                "\"heuristic\":%s,\"accepted\":%s,\"queue_index\":%u,\"queue_last\":%u",
                MEM_U32(parent + 4), MEM_U32(piece + 4), MEM_U16(block + 8), shared, previous, left, degree,
                heuristic ? "true" : "false", accepted ? "true" : "false", MEM_U32(0x100226ac), MEM_U32(0x100226b0));
        ido_end(mode);
    }
    errno = saved_errno;
}

static void ido_choice(uint8_t *mem, uint32_t range, const char *phase) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        ido_begin(mode, name, "ColorPhase");
        fprintf(stderr, ",\"range\":%u,\"phase\":\"%s\",\"internal_color\":%d", MEM_U32(range + 4), phase,
                MEM_S8(range + 32));
        ido_end(mode);
    }
    errno = saved_errno;
    ido_allocation_remark(mem, range, "ColorChoice");
    saved_errno = errno;
    mode = ido_remark_mode(mem, name);
    if (mode) {
        for (uint32_t edge = MEM_U32(range + 56); edge; edge = MEM_U32(edge + 4)) {
            uint32_t other = MEM_U32(edge);
            if (!other)
                continue;
            ido_begin(mode, name, "InterferenceEdge");
            fprintf(stderr, ",\"range\":%u,\"other_range\":%u,\"other_color\":%d", MEM_U32(range + 4),
                    MEM_U32(other + 4), MEM_S8(other + 32));
            ido_end(mode);
        }
    }
    errno = saved_errno;
}

static void ido_seed_selected(uint8_t *mem, uint32_t kept, uint32_t remainder, uint32_t unit) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && kept && remainder && unit) {
        ido_begin(mode, name, "SplitSeedSelected");
        fprintf(stderr,
                ",\"kept_range\":%u,\"remainder_range\":%u,\"block\":%u,\"seed_is_definition\":%s,\"loads\":%u,"
                "\"stores\":%u",
                MEM_U32(kept + 4), MEM_U32(remainder + 4), MEM_U16(MEM_U32(unit) + 8),
                MEM_U8(unit + 20) ? "true" : "false", MEM_U16(unit + 16), MEM_U8(unit + 18));
        ido_end(mode);
    }
    errno = saved_errno;
}

static void ido_interference_origin(uint8_t *mem, uint32_t owner, uint32_t target, uint32_t before0, uint32_t before1,
                                    uint32_t after0, uint32_t after1) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        ido_begin(mode, name, "ForbiddenOrigin");
        fprintf(stderr,
                ",\"cause\":\"colored_interferer\",\"owner_range\":%u,\"range\":%u,\"internal_color\":%d,"
                "\"before\":[\"%08x\",\"%08x\"],\"after\":[\"%08x\",\"%08x\"]",
                MEM_U32(owner + 4), MEM_U32(target + 4), MEM_S8(owner + 32), before0, before1, after0, after1);
        ido_end(mode);
    }
    errno = saved_errno;
}

static void ido_return_origin(uint8_t *mem, uint32_t block, uint32_t chain, uint32_t regclass, uint32_t before0,
                              uint32_t before1, uint32_t after0, uint32_t after1) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        ido_begin(mode, name, "ForbiddenOrigin");
        fprintf(stderr,
                ",\"cause\":\"return_range\",\"block\":%u,\"regclass\":%u,"
                "\"expression\":{\"table\":%u,\"chain\":%u,\"bit\":%u},"
                "\"before\":[\"%08x\",\"%08x\"],\"after\":[\"%08x\",\"%08x\"]",
                MEM_U16(block + 8), regclass, MEM_U16(chain + 4), MEM_U16(chain + 6), MEM_U16(chain + 2), before0,
                before1, after0, after1);
        ido_end(mode);
    }
    errno = saved_errno;
}
static void f_globalcolor(uint8_t *mem, uint32_t sp) {
    ido_original_globalcolor(mem, sp);
    ido_color_snapshot(mem);
}
static void f_spilltemps(uint8_t *mem, uint32_t sp) {
    ido_original_spilltemps(mem, sp);
    ido_slot_snapshot(mem);
}
static void f_spilltemplodstr(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2) {
    ido_original_spilltemplodstr(mem, sp, a0, a1, a2);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        ido_begin(mode, name, "SpillAccess");
        if (mode == 2)
            fprintf(stderr,
                    ",\"ucode_opcode\":%u,\"dtype\":%u,\"m_offset\":%d,"
                    "\"size\":%u,\"block_id\":%u",
                    a0, a1, MEM_S32(a2 + 4), MEM_U32(0x10011ff8), MEM_U32(0x1001c4c4));
        else
            fprintf(stderr, ": ucode-op=%u dtype=%u M-offset=%d size=%u block-id=%u", a0, a1, MEM_S32(a2 + 4),
                    MEM_U32(0x10011ff8), MEM_U32(0x1001c4c4));
        ido_end(mode);
    }
    errno = saved_errno;
}
static void f_split(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3) {
    uint32_t parent = MEM_U32(a0), parent_id = parent ? MEM_U32(parent + 4) : 0;
    int parent_color = parent ? MEM_S8(parent + 32) : 0;
    ido_original_split(mem, sp, a0, a1, a2, a3);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && !MEM_U8(0x1001eb84) && MEM_U32(a0) && MEM_U32(a1)) {
        ido_begin(mode, name, "SplitLineage");
        fprintf(
            stderr,
            ",\"parent_range\":%u,\"parent_color\":%d,\"kept_range\":%u,\"remainder_range\":%u,\"distinct_pieces\":%s",
            parent_id, parent_color, MEM_U32(MEM_U32(a0) + 4), MEM_U32(MEM_U32(a1) + 4),
            MEM_U32(a0) != MEM_U32(a1) ? "true" : "false");
        ido_end(mode);
        ido_begin(mode, name, "SplitAttempt");
        if (mode == 2)
            fprintf(stderr,
                    ",\"new_range\":%u,\"remaining_range\":%u,\"regclass\":%u,"
                    "\"new_color\":%d,\"remaining_color\":%d",
                    MEM_U32(MEM_U32(a0) + 4), MEM_U32(MEM_U32(a1) + 4), a2, MEM_S8(MEM_U32(a0) + 0x20),
                    MEM_S8(MEM_U32(a1) + 0x20));
        else
            fprintf(stderr, ": new-range=%u remaining-range=%u regclass=%u new-color=%d remaining-color=%d",
                    MEM_U32(MEM_U32(a0) + 4), MEM_U32(MEM_U32(a1) + 4), a2, MEM_S8(MEM_U32(a0) + 0x20),
                    MEM_S8(MEM_U32(a1) + 0x20));
        ido_end(mode);
    }
    errno = saved_errno;
}
static void f_reemit(uint8_t *mem, uint32_t sp) {
    ido_original_reemit(mem, sp);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && !MEM_U8(0x1001eb84)) {
        ido_begin(mode, name, "FrameExtent");
        if (mode == 2)
            fprintf(stderr, ",\"temp_displacement\":%d,\"highest_m_definition\":%d,\"stack_reversed\":%s",
                    MEM_S32(0x1001c4b4), MEM_S32(0x1001cc40), MEM_U8(0x1001ebac) ? "true" : "false");
        else
            fprintf(stderr, ": temp-displacement=%d highest-M-definition=%d stack-reversed=%u", MEM_S32(0x1001c4b4),
                    MEM_S32(0x1001cc40), MEM_U8(0x1001ebac));
        ido_end(mode);
    }
    errno = saved_errno;
}

/* increasecount counts reuse of an existing expression, not a hash lookup miss. */
static void f_increasecount(uint8_t *mem, uint32_t sp, uint32_t a0) {
    int saved_errno = errno;
    unsigned before = a0 ? MEM_U16(a0 + 6) : 0;
    ido_original_increasecount(mem, sp, a0);
    saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && a0 && MEM_U8(a0) == 4 && MEM_U16(a0 + 6) > 1) {
        uint32_t block = MEM_U32(a0 + 0x10);
        ido_begin_pass(mode, name, "LocalReuse", "ido-cse");
        fprintf(stderr,
                ",\"expression\":{\"table\":%u,\"chain\":%u,\"address\":%u},"
                "\"block\":%u,\"ucode_opcode\":%u,\"count_before\":%u,\"count_after\":%u,"
                "\"operand_addresses\":[%u,%u],\"killed\":%s,\"anticipated\":%s,\"available\":%s",
                MEM_U16(a0 + 8), MEM_U32(a0 + 0xc), a0, block ? MEM_U16(block + 8) : 0, MEM_U8(a0 + 0x20), before,
                MEM_U16(a0 + 6), MEM_U32(a0 + 0x24), MEM_U32(a0 + 0x28), MEM_U8(a0 + 2) ? "true" : "false",
                MEM_U8(a0 + 0x21) ? "true" : "false", MEM_U8(a0 + 0x22) ? "true" : "false");
        ido_cse_end(mode);
    }
    errno = saved_errno;
}

/* Observe the actual ant/av bit transitions of the global expression check. */
static void f_checkexp_ant_av(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {
    int saved_errno = errno;
    uint32_t bit = MEM_U16(a0 + 2);
    int ant = ido_member(mem, a1 + 0x104, bit), av = ido_member(mem, a1 + 0x114, bit);
    ido_original_checkexp_ant_av(mem, sp, a0, a1);
    saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        ido_begin_pass(mode, name, "AnticipationAvailability", "ido-cse");
        fprintf(stderr,
                ",\"expression\":{\"table\":%u,\"chain\":%u,\"bit\":%u},"
                "\"block\":%u,\"anticipated_before\":%s,\"anticipated_after\":%s,"
                "\"available_before\":%s,\"available_after\":%s",
                MEM_U16(a0 + 4), MEM_U16(a0 + 6), bit, MEM_U16(a1 + 8), ant ? "true" : "false",
                ido_member(mem, a1 + 0x104, bit) ? "true" : "false", av ? "true" : "false",
                ido_member(mem, a1 + 0x114, bit) ? "true" : "false");
        ido_cse_end(mode);
    }
    errno = saved_errno;
}

/* This predicate observes killed operands; it does not identify the killing store/call. */
static uint32_t f_treekilled(uint8_t *mem, uint32_t sp, uint32_t a0) {
    uint32_t result = ido_original_treekilled(mem, sp, a0);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && MEM_U8(a0) == 4) {
        ido_begin_pass(mode, name, "TreeKilledCheck", "ido-cse");
        fprintf(stderr,
                ",\"expression\":{\"table\":%u,\"chain\":%u,\"address\":%u},"
                "\"ucode_opcode\":%u,\"tree_killed\":%s",
                MEM_U16(a0 + 8), MEM_U32(a0 + 0xc), a0, MEM_U8(a0 + 0x20), result ? "true" : "false");
        ido_cse_end(mode);
    }
    errno = saved_errno;
    return result;
}

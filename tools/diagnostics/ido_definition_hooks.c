/* Appended after the shared uopt observers; all guest state is read-only. */
static unsigned ido_definition_phase;

static const char *ido_definition_phase_name(void) {
    return ido_definition_phase == 1 ? "codeimage" : ido_definition_phase == 2 ? "range_build" : "input_or_transform";
}

static void ido_definition_input(uint8_t *mem) {
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode) {
        ido_begin(mode, name, "DefinitionInput");
        fprintf(stderr,
                ",\"dtype\":%u,\"memtype\":%u,\"symbol_block\":%u,\"storage_offset\":%d,\"width\":%u,\"source_file\":%"
                "u,\"source_line\":%u",
                MEM_U8(0x10011ff1) & 31, MEM_U8(0x10011ff1) >> 5, MEM_U32(0x10011ff4), MEM_S32(0x10011ffc),
                MEM_U32(0x10011ff8), ido_definition_file, ido_definition_line);
        ido_end(mode);
    }
    errno = saved_errno;
}

static void f_codeimage(uint8_t *mem, uint32_t sp) {
    unsigned previous = ido_definition_phase;
    ido_definition_phase = 1;
    ido_original_codeimage(mem, sp);
    ido_definition_phase = previous;
}

static void f_makelivranges(uint8_t *mem, uint32_t sp) {
    unsigned previous = ido_definition_phase;
    ido_definition_phase = 2;
    ido_original_makelivranges(mem, sp);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && !MEM_U8(0x1001eb84)) {
        uint32_t table = MEM_U32(0x1001cc30), count = MEM_U32(0x1001cb38);
        for (uint32_t bit = 0; bit < count; ++bit) {
            uint32_t range = MEM_U32(table + 8 * bit + 4);
            if (!range)
                continue;
            for (uint32_t unit = MEM_U32(range + 8); unit; unit = MEM_U32(unit + 4)) {
                if (!MEM_U8(unit + 20))
                    continue;
                ido_begin(mode, name, "DefinitionLiveUnit");
                fprintf(stderr, ",\"range\":%u,\"block\":%u,\"first_store\":true,\"loads\":%u,\"stores\":%u",
                        MEM_U32(range + 4), MEM_U16(MEM_U32(unit) + 8), MEM_U16(unit + 16), MEM_U8(unit + 18));
                ido_end(mode);
            }
        }
    }
    errno = saved_errno;
    ido_definition_phase = previous;
}

static void f_formlivbb(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1, uint32_t a2) {
    uint32_t bit = MEM_U16(a0 + 2), table = MEM_U32(0x1001cc30), count = MEM_U32(0x1001cb38);
    int known = table && bit < count;
    uint32_t prior = known ? MEM_U32(table + 8 * bit + 4) : 0;
    ido_original_formlivbb(mem, sp, a0, a1, a2);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    table = MEM_U32(0x1001cc30);
    uint32_t range = known && table && !MEM_U8(0x1001eb84) ? MEM_U32(table + 8 * bit + 4) : 0;
    if (mode && !prior && range) {
        ido_begin(mode, name, "RangeCreated");
        fprintf(stderr,
                ",\"range\":%u,\"block\":%u,\"phase\":\"%s\",\"dtype\":%u,\"expression_type\":%u,"
                "\"expression\":{\"table\":%u,\"chain\":%u,\"bit\":%u},\"origin_expression_address\":%u",
                MEM_U32(range + 4), MEM_U16(a1 + 8), ido_definition_phase_name(), MEM_U8(a0 + 1), MEM_U8(a0),
                MEM_U16(a0 + 4), MEM_U16(a0 + 6), bit, MEM_U32(a0 + 8));
        if (MEM_U8(a0) == 3 || MEM_U8(a0) == 6)
            fprintf(stderr, ",\"storage_offset\":%d,\"storage_word\":\"%08x\"", MEM_S32(a0 + 16), MEM_U32(a0 + 20));
        ido_end(mode);
    }
    errno = saved_errno;
}

static uint32_t f_newbit(uint8_t *mem, uint32_t sp, uint32_t a0, uint32_t a1) {
    uint32_t result = ido_original_newbit(mem, sp, a0, a1);
    int saved_errno = errno;
    char name[1025];
    int mode = ido_remark_mode(mem, name);
    if (mode && a0 && !MEM_U8(0x1001eb84)) {
        ido_begin(mode, name, "BitAllocated");
        fprintf(stderr,
                ",\"bit\":%u,\"for_range\":%s,\"phase\":\"%s\",\"dtype\":%u,\"expression_type\":%u,"
                "\"expression\":{\"table\":%u,\"chain\":%u}",
                result, a1 ? "true" : "false", ido_definition_phase_name(), MEM_U8(a0 + 1), MEM_U8(a0), MEM_U16(a0 + 4),
                MEM_U16(a0 + 6));
        ido_end(mode);
    }
    errno = saved_errno;
    return result;
}

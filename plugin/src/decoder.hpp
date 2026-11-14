// Processor extension for x64 legacy opcode forms; bytes and patch records are never changed.
struct modern_decoded
{
    uint32 kind, size, modrm, sib, rex, segment, address32, disp_offset, disp_size;
    int64 displacement;
};
static_assert(sizeof(modern_decoded) == 48);
extern "C" bool ntrays_decode_extensions(const uint8* bytes, size_t size, modern_decoded* out);

static const char* const modern_names[] = { NTRAYS_MODERN_INSNS(AS_NAME) };
static int modern_kind(const insn_t& insn)
{
    return insn.itype >= MODERN_FIRST && insn.itype < MODERN_FIRST + qnumber(modern_names)
        ? int(insn.itype - MODERN_FIRST) : -1;
}

struct modern_decoder : event_listener_t
{
    bool hooked;
    explicit modern_decoder(plugmod_t* owner)
        : hooked(ntrays_db_is_pe64() && PH.id == PLFM_386 && hook_event_listener(HT_IDP, this, owner)) {}
    ~modern_decoder() { if (hooked) unhook_event_listener(HT_IDP, this); }

    static int segment(uint32 prefix)
    {
        switch (prefix) {
            case 0x26: return R_es; case 0x2e: return R_cs; case 0x36: return R_ss;
            case 0x3e: return R_ds; case 0x64: return R_fs; case 0x65: return R_gs;
            default: return 0;
        }
    }

    static int analyze(insn_t& insn)
    {
        const segment_t* seg = getseg(insn.ea);
        if (!seg || seg->bitness != 2) return 0;
        const uint8 first = get_byte(insn.ea);
        if (first != 0x0f && first != 0xf2 && first != 0xf3 && first != 0x66 && first != 0x67
            && first != 0x26 && first != 0x2e && first != 0x36 && first != 0x3e && first != 0x64 && first != 0x65
            && (first < 0x40 || first > 0x4f)) return 0;
        uint8 bytes[15];
        const ssize_t count = get_bytes(bytes, sizeof(bytes), insn.ea);
        modern_decoded d{};
        if (count <= 0 || !ntrays_decode_extensions(bytes, size_t(count), &d)) return 0;
        for (auto& op : insn.ops) op = op_t();
        insn.itype = uint16(MODERN_FIRST + d.kind);
        insn.size = uint16(d.size);
        insn.auxpref = aux_use64 | (d.address32 ? 0 : aux_natad);
        insn.rex = uint8(d.rex & ~REX_W); // LKGS always reads a 16-bit selector.
        insn.segpref = uint8(segment(d.segment));
        if (d.kind == 2)
        {
            op_t& op = insn.Op1;
            op.dtype = dt_word;
            op.flags = OF_SHOW;
            op.reg = uint16((d.modrm & 7) | ((d.rex & REX_B) ? 8 : 0));
            if ((d.modrm >> 6) == 3) op.type = o_reg;
            else
            {
                op.hasSIB = d.sib != 256;
                op.sib = uint8(d.sib);
                op.offb = uint8(d.disp_offset);
                op.addr = ea_t(d.displacement);
                const bool no_base = (d.modrm >> 6) == 0 && (op.hasSIB ? (d.sib & 7) == 5 : (d.modrm & 7) == 5);
                op.type = no_base ? o_mem : d.disp_size ? o_displ : o_phrase;
                if (no_base && !op.hasSIB) op.addr += insn.ea + insn.size;
                if (no_base && d.address32) op.addr = uint32(op.addr);
                if (d.disp_size) insn.auxpref |= aux_large | (d.disp_size == 1 ? aux_short : 0);
                const int base = x86_base_reg(insn, op);
                op.segrg = uint16(insn.segpref ? insn.segpref : no_base && !op.hasSIB ? R_cs
                    : base == R_sp || base == R_bp ? R_ss : R_ds);
            }
        }
        return insn.size;
    }

    ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
        try
        {
            if (code == processor_t::ev_ana_insn) return analyze(*va_arg(va, insn_t*));
            if (code == processor_t::ev_out_mnem || code == processor_t::ev_out_insn)
            {
                auto& ctx = *va_arg(va, outctx_t*);
                const int kind = modern_kind(ctx.insn);
                if (kind < 0) return 0;
                ctx.out_custom_mnem(modern_names[kind]);
                if (code == processor_t::ev_out_insn)
                {
                    if (kind == 2) ctx.out_one_operand(0);
                    ctx.set_gen_cmt(); ctx.flush_outbuf();
                }
                return 1;
            }
            if (code == processor_t::ev_emu_insn || code == processor_t::ev_is_ret_insn
                || code == processor_t::ev_is_basic_block_end)
            {
                const insn_t& insn = *va_arg(va, const insn_t*);
                const int kind = modern_kind(insn);
                if (kind < 0) return 0;
                if (code != processor_t::ev_emu_insn) return kind < 2 ? 1 : -1;
                if (kind >= 2) insn.add_cref(insn.ea + insn.size, 0, fl_F);
                if (kind == 2 && insn.Op1.type == o_mem && insn.Op1.segrg != R_fs && insn.Op1.segrg != R_gs)
                {
                    const ea_t address = map_data_ea(insn, insn.Op1);
                    insn.create_op_data(address, insn.Op1);
                    insn.add_dref(address, insn.Op1.offb, dr_R);
                }
                return 1;
            }
        }
        catch (...) {}
        return 0;
    }
};

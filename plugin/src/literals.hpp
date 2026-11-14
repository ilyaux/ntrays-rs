// Windows literal presentation. Preserve values, context types and saved user number formats.
extern "C" int32 ntrays_pool_tag_argument(const char* name, uint64 value);

static bool ntstatus_type(const tinfo_t& type)
{
    qstring name;
    return type.get_size() == 4 && type.get_type_name(&name) && name == "NTSTATUS";
}

struct windows_literals : ctree_visitor_t
{
    bool status_return;
    tinfo_t status_enum;

    explicit windows_literals(cfunc_t* cf) : ctree_visitor_t(CV_FAST), status_return(false)
    {
        func_type_data_t details;
        tinfo_t type;
        status_return = cf->get_func_type(&type) && type.get_func_details(&details) && ntstatus_type(details.rettype);
        status_enum.get_named_type("MACRO_STATUS");
    }

    static bool plain_number(cexpr_t* expr)
    {
        return expr && expr->op == cot_num && expr->type.get_size() == 4
            && expr->n->nf.is_numop() && !expr->n->nf.is_fixed();
    }

    void status(cexpr_t* expr)
    {
        if (!expr) return;
        if (expr->op == cot_cast && expr->type.get_size() == 4)
        {
            status(expr->x);
            return;
        }
        if (expr->op == cot_tern)
        {
            status(expr->y);
            status(expr->z);
            return;
        }
        if (!plain_number(expr) || !status_enum.is_enum()) return;
        // Windows TILs contain both signed NTSTATUS and unsigned DWORD spellings.
        const uint64 values[] = { uint64(int64(int32(expr->n->_value))), uint64(uint32(expr->n->_value)) };
        for (uint64 value : values)
        for (uint32 serial = 0; serial <= 255; ++serial)
        {
            edm_t member;
            if (status_enum.get_edm_by_value(&member, value, DEFMASK64, uchar(serial)) < 0) break;
            // The TIL also contains severity-bit constants, which are not return statuses.
            if (member.name.find("STATUS_") != 0 || member.name.find("STATUS_SEVERITY_") == 0) continue;
            if (uint32(expr->n->_value) == 0 && member.name != "STATUS_SUCCESS") continue;
            if (status_enum.force_tid() == BADADDR) return;
            number_format_t format = expr->n->nf;
            format.flags = enum_flag();
            format.type_name = "MACRO_STATUS";
            format.serial = uchar(serial);
            format.org_nbytes = 4;
            format.props = NF_VALID;
            // The TIL enum can be 64-bit: retain the original arithmetic width with an explicit cast.
            auto constant = std::make_unique<cexpr_t>(*expr);
            constant->n->nf = std::move(format);
            constant->type = status_enum;
            constant->n->_value = member.value;
            cexpr_t replacement;
            replacement.op = cot_cast;
            replacement.ea = expr->ea;
            replacement.type = expr->type;
            replacement.x = constant.release();
            expr->swap(replacement);
            return;
        }
    }

    int idaapi visit_insn(cinsn_t* insn) override
    {
        if (status_return && insn->op == cit_return) status(&insn->creturn->expr);
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (is_relational(expr->op))
        {
            if (ntstatus_type(expr->x->type)) status(expr->y);
            if (ntstatus_type(expr->y->type)) status(expr->x);
        }
        if (expr->op != cot_call || !expr->a) return 0;
        const cexpr_t* target = expr->x;
        if (target->op == cot_ptr) target = target->x;
        qstring name;
        if (target->op == cot_obj) get_ea_name(&name, target->obj_ea);
        else if (target->op == cot_helper) name = target->helper;
        else return 0;
        for (size_t i = 0; i < expr->a->size(); ++i)
        {
            auto& arg = (*expr->a)[i];
            if (plain_number(&arg) && ntrays_pool_tag_argument(name.c_str(), arg.n->_value) == int32(i))
                arg.n->nf.flags = char_flag();
        }
        return 0;
    }
};

static void format_windows_literals(cfunc_t* cf)
{
    windows_literals visitor(cf);
    visitor.apply_to(&cf->body, nullptr);
}

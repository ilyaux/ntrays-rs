// Explicit syscall actions, owned by the plugmod for the current database.
#pragma once

extern "C" bool ntrays_component_enabled(void* state, uint32 component);
extern "C" uint32 ntrays_ui_api_count();
extern "C" bool ntrays_ui_api_row(uint32 index, uint32 field, char* out, size_t cap);
extern "C" int64 ntrays_ui_api_selection(void* state, uint64 ea);
extern "C" bool ntrays_ui_set_api(void* state, uint64 ea, uint32 index);
extern "C" uint32 ntrays_ui_preset_count();
extern "C" bool ntrays_ui_preset_row(uint32 index, char* out, size_t cap);
extern "C" int64 ntrays_ui_preset_selection(void* state);
extern "C" bool ntrays_ui_set_preset(void* state, uint32 index);
extern "C" bool ntrays_ui_import_map(void* state, const char* path);

extern "C" bool ntrays_ui_is_syscall(uint64 ea)
{
    try
    {
        if (!ntrays_db_is_pe64() || !is_code(get_flags(ea))) return false;
        insn_t insn;
        if (decode_insn(&insn, ea) <= 0) return false;
        return insn.itype == NN_syscall
            || (insn.itype == NN_int && insn.Op1.type == o_imm && insn.Op1.value == 0x2E);
    }
    catch (...) { return false; }
}

// A token can have a fictitious EA or no EA at all. Resolve its nearest call;
// never substitute the function entry or an unrelated statement's address.
static ea_t syscall_selection_ea(vdui_t* vu, input_device_t device)
{
    if (!vu || !vu->cfunc || !vu->mba || !vu->get_current_item(device) || !vu->in_ctree()) return BADADDR;
    ea_t fict = BADADDR;
    if (vu->item.citype == VDI_EXPR && vu->item.it)
    {
        struct selected_call : ctree_visitor_t
        {
            const citem_t* target;
            ea_t ea = BADADDR;
            explicit selected_call(const citem_t* item) : ctree_visitor_t(CV_PARENTS), target(item) {}
            int visit(citem_t* item)
            {
                if (!item || item != target) return 0;
                if (item->op == cot_call) ea = item->ea;
                else
                {
                    for (size_t i = parents.size(); i-- > 0;)
                        // The ctree visitor's parent path can contain a null root sentinel.
                        if (parents[i] && parents[i]->op == cot_call) { ea = parents[i]->ea; break; }
                    if (ea == BADADDR) ea = item->ea;
                }
                return 1;
            }
            int idaapi visit_expr(cexpr_t* expr) override { return visit(expr); }
            int idaapi visit_insn(cinsn_t* insn) override { return visit(insn); }
        } selected(vu->item.it);
        selected.apply_to(&vu->cfunc->body, nullptr);
        fict = selected.ea;
    }
    else if (vu->tail.citype == VDI_TAIL) fict = vu->tail.loc.ea;
    else if (vu->head.citype == VDI_TAIL) fict = vu->head.loc.ea;
    if (fict == BADADDR) return BADADDR;
    ea_t ea = vu->mba->map_fict_ea(fict);
    return vu->cfunc->mba->range_contains(ea) && ntrays_ui_is_syscall(ea) ? ea : BADADDR;
}

struct syscall_api_chooser : chooser_t
{
    static constexpr int widths[] = {35, 90};
    static constexpr const char* columns[] = {"API", "Signature"};
    syscall_api_chooser() : chooser_t(CH_KEEP | CH_MODAL, 2, widths, columns, "NtRays: Set syscall API") {}
    size_t idaapi get_count() const override { return ntrays_ui_api_count(); }
    void idaapi get_row(qstrvec_t* out, int*, chooser_item_attrs_t*, size_t index) const override
    {
        char text[4096];
        for (uint32 field = 0; field < 2; ++field)
            if (ntrays_ui_api_row(uint32(index), field, text, sizeof(text))) (*out)[field] = text;
    }
};

struct syscall_version_chooser : chooser_t
{
    static constexpr int widths[] = {110};
    static constexpr const char* columns[] = {"Explicit syscall map (servicing revisions can differ)"};
    syscall_version_chooser() : chooser_t(CH_KEEP | CH_MODAL, 1, widths, columns, "NtRays: Set Windows version") {}
    size_t idaapi get_count() const override { return ntrays_ui_preset_count(); }
    void idaapi get_row(qstrvec_t* out, int*, chooser_item_attrs_t*, size_t index) const override
    {
        char text[1024];
        if (ntrays_ui_preset_row(uint32(index), text, sizeof(text))) (*out)[0] = text;
    }
};

struct syscall_actions
{
    static constexpr const char* api_action = "ntrays-rs:set_syscall_api";
    static constexpr const char* version_action = "ntrays-rs:set_windows_version";
    void* state;
    const plugmod_t* owner;
    bool registered_api = false;
    bool registered_version = false;

    struct handler : action_handler_t
    {
        syscall_actions& actions;
        bool api;
        bool bound = false;
        TWidget* widget = nullptr;
        ea_t entry = BADADDR;
        ea_t ea = BADADDR;
        handler(syscall_actions& owner, bool is_api) : actions(owner), api(is_api) {}
        handler(syscall_actions& owner, TWidget* w, ea_t f, ea_t address)
            : actions(owner), api(true), bound(true), widget(w), entry(f), ea(address) {}
        int idaapi activate(action_activation_ctx_t* ctx) override
        {
            try { return actions.activate(ctx, api, bound, widget, entry, ea); }
            catch (...) { warning("NtRays could not apply the syscall selection; see Output."); return 0; }
        }
        action_state_t idaapi update(action_update_ctx_t* ctx) override
        {
            try
            {
                if (ctx->widget_type != BWN_PSEUDOCODE || !ntrays_db_is_pe64()
                    || !ntrays_component_enabled(actions.state, 1)) return AST_DISABLE_FOR_WIDGET;
                if (api && !bound && syscall_selection_ea(get_widget_vdui(ctx->widget), USE_KEYBOARD) == BADADDR)
                    return AST_DISABLE_FOR_WIDGET;
                return AST_ENABLE_FOR_WIDGET;
            }
            catch (...) { return AST_DISABLE_FOR_WIDGET; }
        }
    } api_handler, version_handler;

    syscall_actions(void* s, const plugmod_t* owner)
        : state(s), owner(owner), api_handler(*this, true), version_handler(*this, false)
    {
        action_desc_t api = ACTION_DESC_LITERAL_PLUGMOD(api_action, "Set syscall ~A~PI...", &api_handler, owner, nullptr, "Choose a typed Nt API for this syscall instruction", -1);
        action_desc_t version = ACTION_DESC_LITERAL_PLUGMOD(version_action, "Set ~W~indows version...", &version_handler, owner, nullptr, "Choose an explicit map or import a syscall DLL", -1);
        registered_api = register_action(api);
        registered_version = register_action(version);
        if (!registered_api || !registered_version) msg("[ntrays-rs] could not register all syscall actions\n");
    }
    ~syscall_actions()
    {
        if (registered_api) unregister_action(api_action);
        if (registered_version) unregister_action(version_action);
    }
    syscall_actions(const syscall_actions&) = delete;
    syscall_actions& operator=(const syscall_actions&) = delete;

    void popup(TWidget* widget, TPopupMenu* menu, vdui_t* vu)
    {
        if (!ntrays_db_is_pe64() || !ntrays_component_enabled(state, 1)) return;
        ea_t ea = syscall_selection_ea(vu, USE_MOUSE);
        if (registered_api && ea != BADADDR)
        {
            // A popup owns this exact target. Dismissing it cannot leave a stale address for a later action.
            auto* action = new handler(*this, widget, vu->cfunc->entry_ea, ea);
            action_desc_t desc = DYNACTION_DESC_LITERAL("Set syscall ~A~PI...", action, nullptr, "Choose a typed Nt API for this syscall instruction", -1);
            desc.owner = owner;
            desc.flags |= ADF_OT_PLUGMOD;
            if (!attach_dynamic_action_to_popup(nullptr, menu, desc)) delete action;
        }
        if (registered_version) attach_action_to_popup(widget, menu, version_action);
    }

    int activate(action_activation_ctx_t* ctx, bool api, bool bound, TWidget* widget, ea_t entry, ea_t address)
    {
        if (ctx->widget_type != BWN_PSEUDOCODE || !ntrays_db_is_pe64() || !ntrays_component_enabled(state, 1)) return 0;
        vdui_t* vu = get_widget_vdui(ctx->widget);
        if (!vu || !vu->cfunc) return 0;
        bool committed = false;
        if (api)
        {
            if (bound && (ctx->widget != widget || vu->cfunc->entry_ea != entry)) return 0;
            ea_t ea = bound ? address : syscall_selection_ea(vu, USE_KEYBOARD);
            if (ea == BADADDR || !ntrays_ui_is_syscall(ea)) return 0;
            syscall_api_chooser chooser;
            ssize_t current = ntrays_ui_api_selection(state, ea);
            ssize_t choice = chooser.choose(current < 0 ? 0 : current);
            if (choice < 0) return 0;
            committed = ntrays_ui_set_api(state, ea, uint32(choice));
        }
        else
        {
            syscall_version_chooser chooser;
            ssize_t current = ntrays_ui_preset_selection(state);
            ssize_t choice = chooser.choose(current < 0 ? 0 : current);
            if (choice < 0) return 0;
            if (choice == 1)
            {
                const char* path = ask_file(false, "*.dll", "NtRays: select ntdll.dll or win32u.dll");
                if (!path) return 0;
                committed = ntrays_ui_import_map(state, path);
            }
            else
            {
                if (choice >= 2 && ask_yn(ASKBTN_NO,
                    "This is an explicit snapshot; serviced Windows DLLs can have different syscall numbers.\n"
                    "Use only a matching snapshot, or import the exact ntdll.dll/win32u.dll instead.\n\nApply this map to the current database?") != ASKBTN_YES) return 0;
                committed = ntrays_ui_set_preset(state, uint32(choice));
            }
        }
        if (!committed)
        {
            warning("NtRays could not save the syscall selection. Stored data may be protected or the file invalid; see Output for details.");
            return 0;
        }
        clear_cached_cfuncs();
        vu->refresh_view(true);
        return 1;
    }
};

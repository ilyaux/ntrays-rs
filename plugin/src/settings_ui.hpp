// Native SDK form. Rust validates and commits the same options used by automated plugin runs.
extern "C" uint64 ntrays_settings_value(void* state);
extern "C" bool ntrays_settings_writable(void* state);
extern "C" bool ntrays_settings_apply(void* state, uint64 value);

extern "C" bool ntrays_settings_dialog(void* state)
{
    try
    {
        if ( !ntrays_settings_writable(state) )
        {
            warning("NtRays settings have an unsupported or unreadable format.\nThe stored data is preserved; settings are read-only.");
            return false;
        }
        const uint64 raw = ntrays_settings_value(state);
        ushort enabled = ushort(raw & 1);
        ushort components = ushort((raw >> 8) & 0x3f);
        ushort hvl = ushort((raw >> 1) & 1);
        ushort logs = ushort((raw >> 16) & 3);
        static const char form[] =
            "STARTITEM 0\n"
            "NtRays settings\n\n"
            "Settings apply to this database only.\n"
            "Existing IDA patches, segments and applied types are not undone.\n\n"
            "<Enable NtRays:C>>\n\n"
            "<##Components##Instruction lifters (including paging and trap frames):C>\n"
            "<Typed syscall lifting and syscall menus:C>\n"
            "<Kernel optimizers:C>\n"
            "<Type/ABI fixes and Windows constant formatting:C>\n"
            "<RSB patches and flush helper:C>\n"
            "<Create KUSER_SHARED_DATA mapping:C>>\n\n"
            "<Fold Hvl enlightenments (may remove real code paths):C>>\n\n"
            "<##Output messages##Errors only:R>\n"
            "<Informational:R>\n"
            "<Verbose (per-pass diagnostics):R>>\n\n";
        if ( ask_form(form, &enabled, &components, &hvl, &logs) != 1 ) return true;
        const uint64 value = (raw & 0xffffffffff000000ull) | uint64(enabled & 1)
            | (uint64(hvl & 1) << 1) | (uint64(components) << 8) | (uint64(logs) << 16);
        return ntrays_settings_apply(state, value);
    }
    catch ( ... ) { return false; }
}

extern "C" void ntrays_ui_refresh()
{
    try
    {
        clear_cached_cfuncs();
        TWidget* widget = get_current_viewer();
        if ( widget && get_widget_type(widget) == BWN_PSEUDOCODE )
            if ( vdui_t* vu = get_widget_vdui(widget) ) vu->refresh_view(true);
        refresh_idaview_anyway();
    }
    catch ( ... ) {}
}

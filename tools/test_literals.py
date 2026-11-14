"""Build a synthetic PE and check Windows literal formats through the real plugmod, without a GUI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

SOURCE = r'''
typedef long NTSTATUS;
typedef unsigned long ULONG;
typedef unsigned __int64 SIZE_T;
#define API __declspec(dllexport) __declspec(noinline)
API void *ExAllocatePool2(SIZE_T flags, SIZE_T size, ULONG tag) { return (void *)(SIZE_T)(tag + flags + size); }
API void ExFreePoolWithTag(void *p, ULONG tag) { *(volatile ULONG *)p = tag; }
API void *OtherCall(SIZE_T flags, SIZE_T size, ULONG tag) { return (void *)(SIZE_T)(tag + flags - size); }
API NTSTATUS status_return(void) { return (NTSTATUS)0xC0000022; }
API NTSTATUS status_success(void) { return 0; }
API NTSTATUS status_user(void) { return (NTSTATUS)0xC0000022; }
API NTSTATUS status_unknown(void) { return (NTSTATUS)0xDEAD1234; }
API long integer_return(void) { return (long)0xC0000022; }
API NTSTATUS status_choice(int n) { if (n) return (NTSTATUS)0xC0000022; return (NTSTATUS)0xC000000D; }
API int status_eq(NTSTATUS s) { return s == (NTSTATUS)0xC0000022; }
API int status_less(NTSTATUS s) { return s < (NTSTATUS)0xC0000022; }
API int integer_eq(long s) { return s == (long)0xC0000022; }
API void *pool_tag(void) { return ExAllocatePool2(0, 64, 'Tag1'); }
API void *pool_user(void) { return ExAllocatePool2(0, 64, 'Tag1'); }
API void *pool_bad(void) { return ExAllocatePool2(0, 64, 1); }
API void *pool_other(void) { return OtherCall(0, 64, 'Tag1'); }
API void *pool_wrong_arg(void) { return ExAllocatePool2('Tag1', 64, 1); }
API void pool_free(void *p) { ExFreePoolWithTag(p, 'Tag1'); }
'''
DECLS = {
    'ExAllocatePool2': 'void *ExAllocatePool2(unsigned __int64 flags, unsigned __int64 size, unsigned int tag);',
    'ExFreePoolWithTag': 'void ExFreePoolWithTag(void *p, unsigned int tag);',
    'OtherCall': 'void *OtherCall(unsigned __int64 flags, unsigned __int64 size, unsigned int tag);',
    **{name: f'NTSTATUS {name}(void);' for name in ('status_return', 'status_success', 'status_user', 'status_unknown')},
    'status_choice': 'NTSTATUS status_choice(int n);',
    **{name: f'int {name}(NTSTATUS s);' for name in ('status_eq', 'status_less')},
    'integer_return': 'long integer_return(void);', 'integer_eq': 'int integer_eq(long s);',
    **{name: f'void *{name}(void);' for name in ('pool_tag', 'pool_user', 'pool_bad', 'pool_other', 'pool_wrong_arg')},
    'pool_free': 'void pool_free(void *p);',
}
CASES = [name for name in DECLS if name not in ('ExAllocatePool2', 'ExFreePoolWithTag', 'OtherCall')]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def worker(cfg):
    sys.path.insert(0, str(Path(cfg['ida']) / 'idalib/python'))
    import idapro
    import ida_auto, ida_bytes, ida_hexrays as hx, ida_idaapi, ida_loader, ida_name, ida_typeinf as ti
    assert idapro.open_database(cfg['binary'], True) == 0
    try:
        ida_auto.auto_wait()
        assert hx.init_hexrays_plugin() or (ida_loader.load_plugin('hexx64') and hx.init_hexrays_plugin())
        addresses = {name: ida_name.get_name_ea(ida_idaapi.BADADDR, name) for name in DECLS}
        assert all(ea != ida_idaapi.BADADDR for ea in addresses.values())
        for name, decl in DECLS.items():
            t = ti.tinfo_t()
            assert ti.parse_decl(t, None, decl, ti.PT_SIL) and ti.apply_tinfo(addresses[name], t, ti.TINFO_DEFINITE), name
        hx.clear_cached_cfuncs()

        class Capture(hx.ctree_visitor_t):
            def __init__(self):
                super().__init__(hx.CV_FAST)
                self.shape, self.numbers, self.enum_casts = [], [], {}
            def visit_expr(self, expr):
                if expr.op == hx.cot_cast and expr.x.op == hx.cot_num and expr.x.n.nf.is_enum() and expr.type.get_size() == 4:
                    self.enum_casts[(expr.x.ea, expr.x.n._value, expr.x.n.nf.opnum)] = (str(expr.type), expr.x.n.value(expr.type))
                    return 0
                ty, value = (str(expr.type), expr.n._value if expr.op == hx.cot_num else None)
                if expr.op == hx.cot_num:
                    ty, value = self.enum_casts.get((expr.ea, expr.n._value, expr.n.nf.opnum), (ty, value))
                self.shape.append((expr.op, ty, value))
                if expr.op == hx.cot_num:
                    nf = expr.n.nf
                    self.numbers.append({'ea': expr.ea, 'value': value, 'opnum': ord(nf.opnum),
                        'enum': nf.is_enum(), 'char': nf.is_char(), 'props': ord(nf.props), 'type_name': nf.type_name})
                return 0

        def capture(cached=False):
            result = {}
            for name in CASES:
                failure = hx.hexrays_failure_t()
                cf = hx.decompile(addresses[name], failure, 0 if cached else hx.DECOMP_NO_CACHE)
                assert cf, f'{name}: {failure.desc()}'
                v = Capture(); v.apply_to(cf.body, None)
                result[name] = {'text': str(cf), 'shape': v.shape, 'numbers': v.numbers}
            return result

        def saved_formats(name):
            m = hx.restore_user_numforms(addresses[name])
            if m is None: return []
            try:
                rows = []; it = hx.user_numforms_begin(m); end = hx.user_numforms_end(m)
                while it != end:
                    loc, nf = hx.user_numforms_first(it), hx.user_numforms_second(it)
                    rows.append((loc.ea, loc.opnum, nf.flags, nf.props, nf.type_name, nf.serial))
                    it = hx.user_numforms_next(it)
                return rows
            finally: hx.user_numforms_free(m)

        before = capture()
        for name in ('status_user', 'pool_user'):
            number = next(n for n in before[name]['numbers'] if n['value'] & 0xffffffff in
                (int.from_bytes(b'Tag1', 'big'), 0xc0000022))
            m = hx.user_numforms_new()
            try:
                nf = hx.number_format_t(number['opnum']); nf.flags = ida_bytes.dec_flag(); nf.props = chr(hx.NF_FIXED)
                hx.user_numforms_insert(m, hx.operand_locator_t(number['ea'], number['opnum']), nf)
                hx.save_user_numforms(addresses[name], m)
            finally: hx.user_numforms_free(m)
        preserved = {name: saved_formats(name) for name in CASES}
        before = capture()
        plugin = ida_loader.load_plugin(cfg['plugin']); assert plugin
        after = capture()
        Path(cfg['result']).with_name('observed.json').write_text(json.dumps({'before': before, 'after': after}, indent=2))
        enum = ti.tinfo_t(); found = enum.get_named_type('MACRO_STATUS')
        ret = ti.tinfo_t(); hx.decompile(addresses['status_return']).get_func_type(ret)
        details = ti.func_type_data_t(); ret.get_func_details(details)
        Path(cfg['result']).with_name('environment.json').write_text(json.dumps({'enum_found': found,
            'enum_size': enum.get_size(), 'enum_width': enum.get_enum_width(), 'return_name': details.rettype.get_type_name(),
            'return_size': details.rettype.get_size()}, indent=2))
        assert all(before[n]['shape'] == after[n]['shape'] for n in CASES), 'literal formatting changed ctree values/types/operations'
        assert all([v['value'] for v in before[n]['numbers']] == [v['value'] for v in after[n]['numbers']] for n in CASES)
        assert 'STATUS_ACCESS_DENIED' in after['status_return']['text']
        assert 'STATUS_SUCCESS' in after['status_success']['text']
        assert 'STATUS_ACCESS_DENIED' in after['status_eq']['text']
        assert 'STATUS_ACCESS_DENIED' in after['status_less']['text']
        assert 'STATUS_ACCESS_DENIED' in after['status_choice']['text'] and 'STATUS_INVALID_PARAMETER' in after['status_choice']['text']
        for name in ('status_unknown', 'integer_return', 'integer_eq', 'status_user'):
            assert not any(n['enum'] for n in after[name]['numbers']), name
        for name in ('pool_tag', 'pool_free'):
            assert "'Tag1'" in after[name]['text'], after[name]['text']
        for name in ('pool_bad', 'pool_other', 'pool_wrong_arg', 'pool_user'):
            assert not any(n['char'] for n in after[name]['numbers']), name
        assert preserved == {name: saved_formats(name) for name in CASES}, 'plugin wrote saved number formats'
        capture(cached=True)
        for enabled, components in ((True, 0x37), (False, 0x3f), (True, 0x3f)):
            raw = 0x4e54525301000000 | int(enabled) | (components << 8) | (1 << 16)
            assert ida_loader.run_plugin(plugin, raw)
            row = capture(cached=True)
            active = enabled and components == 0x3f
            assert ('STATUS_ACCESS_DENIED' in row['status_return']['text']) == active
            assert any(n['char'] for n in row['pool_tag']['numbers']) == active
        # The zero alias chosen by TIL ordering must not turn success into a wait label.
        data = ti.enum_type_data_t(); data.set_nbytes(8)
        data.push_back(ti.edm_t('STATUS_WAIT_0', 0)); data.push_back(ti.edm_t('STATUS_SUCCESS', 0))
        aliases = ti.tinfo_t(); assert aliases.create_enum(data)
        assert aliases.set_named_type(None, 'MACRO_STATUS', ti.NTF_REPLACE) == ti.TERR_OK
        hx.clear_cached_cfuncs()
        row = capture()
        assert 'STATUS_SUCCESS' in row['status_success']['text'] and 'STATUS_WAIT_0' not in row['status_success']['text']
        assert aliases.get_enum_nmembers() == 2
        # A conflicting local type must be preserved and formatting must fail closed.
        local = ti.tinfo_t(ti.BTF_UINT32)
        assert local.set_named_type(None, 'MACRO_STATUS', ti.NTF_REPLACE) == ti.TERR_OK
        hx.clear_cached_cfuncs()
        row = capture()
        assert not any(n['enum'] for n in row['status_return']['numbers'])
        assert 'STATUS_ACCESS_DENIED' not in row['status_return']['text']
        assert ti.del_named_type(None, 'MACRO_STATUS', ti.NTF_TYPE)
        assert preserved == {name: saved_formats(name) for name in CASES}
        Path(cfg['result']).write_text(json.dumps({'status': 'PASS', 'cases': len(CASES), 'ida': list(idapro.get_library_version()),
            'hexrays': hx.get_hexrays_version(), 'plugin_sha256': digest(cfg['plugin']), 'before': before, 'after': after,
            'checks': ['ctree shape/type/value preservation', 'typed NTSTATUS returns/comparisons', 'pool API and argument specificity',
                'unknown values and plain integers untouched', 'explicit user formats preserved', 'no saved numform writes',
                'master/component disable/enable cache refresh', 'canonical STATUS_SUCCESS despite alias order',
                'conflicting local enum type preserved']} ,indent=2))
    finally: idapro.close_database(False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ('ida', 'plugin', 'output'): p.add_argument('--' + arg, type=Path, required=True)
    p.add_argument('--vcvars', type=Path, default=Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'))
    args = p.parse_args(); out = args.output.resolve(); repo = Path(__file__).resolve().parents[1]
    if out.exists() or out == repo or repo in out.parents: p.error('choose a fresh output directory outside the repository')
    out.mkdir(parents=True); (out/'fixture.c').write_text(SOURCE)
    batch = f'@call "{args.vcvars}" >nul 2>&1\n@cd /d "{out}"\n@cl /nologo /c /Od /GS- /Zl fixture.c && link /nologo /dll /noentry /opt:noicf /out:fixture.dll fixture.obj\n'
    (out/'build.bat').write_text(batch)
    with (out/'build.log').open('w') as log: subprocess.run(['cmd', '/c', str(out/'build.bat')],check=True,stdout=log,stderr=subprocess.STDOUT,timeout=120)
    rows = []
    for mode in ('first', 'repeat'):
        work = out/mode; work.mkdir(); shutil.copyfile(out/'fixture.dll',work/'fixture.dll')
        cfg = {'ida': str(args.ida.resolve()), 'plugin': str(args.plugin.resolve()), 'binary': str(work/'fixture.dll'), 'result': str(work/'result.json')}
        (work/'config.json').write_text(json.dumps(cfg)); env = dict(os.environ, IDADIR=cfg['ida'], IDAUSR=str(work/'idausr'))
        with (work/'process.log').open('w') as log:
            subprocess.run([sys.executable,'-I',str(Path(__file__).resolve()),'--worker',str(work/'config.json')],check=True,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=120)
        rows.append(json.loads((work/'result.json').read_text()))
    assert rows[0] == rows[1], 'literal output was not reproducible'
    (out/'summary.json').write_text(json.dumps({'status':'PASS','cases':rows[0]['cases'],'repeat_differences':0,
        'plugin_sha256':digest(args.plugin),'script_sha256':digest(__file__),'checks':rows[0]['checks']},indent=2))
    print((out/'summary.json').read_text())


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker': worker(json.loads(Path(sys.argv[2]).read_text()))
    else: main()

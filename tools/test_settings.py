"""Live settings checks through the real plugmod run API; fixtures and reports stay outside the repo.

The nonzero plugin run argument is the packed versioned settings value. Zero opens the GUI dialog.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def options(enabled=True, components=0x3f, hvl=False, level=1):
    return 0x4e54525301000000 | int(enabled) | (int(hvl) << 1) | (components << 8) | (level << 16)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def worker(cfg):
    sys.path.insert(0, str(Path(cfg['ida']) / 'idalib/python'))
    import idapro
    idapro.enable_console_messages(True)
    import ida_auto, ida_hexrays, ida_idaapi, ida_loader, ida_name, ida_netnode

    results = []
    for database, phase in cfg['databases']:
        assert idapro.open_database(database, False) == 0
        try:
            case = cfg['case']
            node = ida_netnode.netnode('$ ntrays-rs', 0, True)
            prepared = {
                'disabled': options(False),
                'future': options() ^ (3 << 24),
                'corrupt': options() | (1 << 7),
                'errors': options(level=0),
                'verbose': options(level=2),
                'hvl-cache': options(components=0x1f),
            }.get(case)
            if prepared is not None and phase == 'first':
                assert node.altset(3, prepared)
            before = int(node.altval(3))
            if not ida_hexrays.init_hexrays_plugin():
                assert ida_loader.load_plugin('hexx64')
                assert ida_hexrays.init_hexrays_plugin()
            plugin = ida_loader.load_plugin(cfg['plugin'])
            assert plugin
            ida_auto.auto_wait()
            if case == 'hvl-cache':
                import ida_segment

                def hvl_call():
                    address = ida_name.get_name_ea(ida_idaapi.BADADDR, 'KeYieldProcessorEx')
                    assert address != ida_idaapi.BADADDR
                    cf = ida_hexrays.decompile(address)
                    assert cf is not None
                    text = str(cf)
                    del cf
                    return 'HvlNotifyLongSpinWait' in text

                assert hvl_call(), 'default Hvl opt-in unexpectedly enabled'
                assert ida_loader.run_plugin(plugin, options(components=0x1f, hvl=True))
                assert not hvl_call(), 'Hvl toggle kept stale default output'
                assert ida_loader.run_plugin(plugin, options(components=0x1b, hvl=True))
                assert hvl_call(), 'optimizer disable kept folded output'
                assert ida_loader.run_plugin(plugin, options(components=0x1f, hvl=True))
                assert not hvl_call()
                assert ida_segment.get_segm_by_name('.kkuser') is None
                assert ida_segment.rebase_program(0x100000, ida_segment.MSF_FIXONCE) == 0
                ida_auto.auto_wait()
                assert not hvl_call(), 'warm fold cache did not resolve new global addresses after rebase'
                assert ida_loader.run_plugin(plugin, options(components=0x1f, hvl=False))
                assert hvl_call(), 'Hvl disable kept stale folded output after rebase'
                results.append({'case': case, 'phase': phase, 'success': True, 'warm_rebase_delta': 0x100000})
                continue
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, 'NtClose')
            if ea == ida_idaapi.BADADDR:
                ea = ida_name.get_name_ea(ida_idaapi.BADADDR, 'OpaqueClose')
            assert ea != ida_idaapi.BADADDR
            # Capture the map first, then remove the function-name shortcut from resolution.
            assert ida_name.set_name(ea, 'OpaqueClose')

            def typed():
                cf = ida_hexrays.decompile(ea)  # Deliberately use the normal cache.
                assert cf is not None
                text = str(cf)
                del cf
                return bool(re.search(r'\bNtClose\s*\(', text))

            if case == 'toggle':
                if phase == 'first':
                    assert typed()
                    assert not ida_loader.run_plugin(plugin, 123), 'invalid settings accepted'
                    assert int(node.altval(3)) == before, 'invalid run changed stored settings'
                    assert typed()
                    # Turning off just the syscall component invalidates the same function's cache.
                    assert ida_loader.run_plugin(plugin, options(components=0x3d))
                    assert not typed(), 'stale typed syscall after disabling component'
                    # Syscalls are independent of the general instruction-lifter checkbox.
                    assert ida_loader.run_plugin(plugin, options(components=2))
                    assert typed()
                    assert ida_loader.run_plugin(plugin, options(False))
                    assert not typed(), 'stale typed syscall after disabling master'
                    assert int(node.altval(3)) == options(False)
                elif phase == 'reopen-disabled':
                    assert before == options(False), 'destructor changed disabled preference'
                    assert not typed()
                    assert ida_loader.run_plugin(plugin, options())
                    assert typed()
                    assert int(node.altval(3)) == options()
                else:
                    assert before == options(), 'enabled preference did not survive close/reopen'
                    assert typed()
            elif case in ('future', 'corrupt'):
                assert not typed()
                assert not ida_loader.run_plugin(plugin, options()), 'protected settings overwritten'
                assert int(node.altval(3)) == before == prepared
                assert not ida_netnode.netnode.exist('$ ntrays-rs syscall'), 'disabled plugin wrote a syscall map'
            elif case == 'disabled':
                assert before == options(False)
                assert not typed()
                assert not ida_netnode.netnode.exist('$ ntrays-rs syscall'), 'disabled startup wrote a syscall map'
            elif case in ('errors', 'verbose'):
                assert typed()
            elif case == 'isolation':
                if phase == 'disable-a':
                    assert typed()
                    assert ida_loader.run_plugin(plugin, options(False))
                    assert not typed()
                elif phase == 'fresh-b':
                    assert before == 0 and typed(), 'database A preference leaked into B'
                else:
                    assert before == options(False) and not typed(), 'database B changed A preference'
            results.append({'case': case, 'phase': phase, 'stored': int(node.altval(3)), 'success': True})
        finally:
            idapro.close_database(True)
    Path(cfg['result']).write_text(json.dumps(results, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ida', 'plugin', 'base', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--kernel-base', type=Path, help='optional pristine kernel IDB for Hvl/cache/rebase checks')
    args = parser.parse_args()
    args.ida, args.plugin, args.base, args.output = (p.resolve() for p in (args.ida, args.plugin, args.base, args.output))
    repo = Path(__file__).resolve().parents[1]
    if args.output.exists() or args.output == repo or repo in args.output.parents:
        parser.error('choose a fresh output directory outside the repository')
    args.output.mkdir(parents=True)
    before_hash = sha256(args.base)
    summary = {'base_sha256': before_hash, 'plugin_sha256': sha256(args.plugin), 'script_sha256': sha256(__file__), 'cases': []}
    cases = ['toggle', 'disabled', 'future', 'corrupt', 'errors', 'verbose', 'isolation']
    if args.kernel_base:
        args.kernel_base = args.kernel_base.resolve()
        summary['kernel_base_sha256'] = sha256(args.kernel_base)
        cases.append('hvl-cache')
    for case in cases:
        folder = args.output / case
        folder.mkdir()
        database = folder / 'working.i64'
        shutil.copyfile(args.kernel_base if case == 'hvl-cache' else args.base, database)
        phases = ['first']
        if case == 'toggle':
            phases += ['reopen-disabled', 'reopen-enabled']
        databases = [(str(database), phase) for phase in phases]
        if case == 'isolation':
            second = folder / 'second.i64'
            shutil.copyfile(args.base, second)
            databases = [(str(database), 'disable-a'), (str(second), 'fresh-b'), (str(database), 'reopen-a')]
        cfg = {'case': case, 'ida': str(args.ida), 'plugin': str(args.plugin), 'databases': databases, 'result': str(folder / 'result.json')}
        config = folder / 'config.json'
        config.write_text(json.dumps(cfg, indent=2) + '\n')
        user = folder / 'idausr'
        user.mkdir()
        env = dict(os.environ, IDADIR=str(args.ida), IDAUSR=str(user))
        env.pop('IDA_IS_INTERACTIVE', None)
        with (folder / 'worker.log').open('w', encoding='utf-8') as log:
            subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), '--worker', str(config)],
                           cwd=folder, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180, check=True)
        log = (folder / 'worker.log').read_text(encoding='utf-8', errors='replace')
        if case == 'errors':
            assert '[ntrays-rs] loaded' not in log and '[ntrays-rs] lift ' not in log
        if case == 'verbose':
            assert '[ntrays-rs] lift ' in log
        summary['cases'] += json.loads((folder / 'result.json').read_text())
    assert sha256(args.base) == before_hash
    if args.kernel_base:
        assert sha256(args.kernel_base) == summary['kernel_base_sha256']
    summary['source_unchanged'] = True
    summary['status'] = 'PASS'
    summary['limits'] = 'Real plugmod run API under idalib; native dialog acceptance/cancel/hotkey require interactive GUI checks.'
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        worker(json.loads(Path(sys.argv[2]).read_text()))
    else:
        main()

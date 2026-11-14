//! Compare an explicitly selected release preset with the user's own ntdll/win32u files.
use ntrays_core::syscall::read_syscall_map;
use ntrays_core::syscall_presets::find;
use std::collections::BTreeMap;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: check_syscall_preset <preset-id> <ntdll.dll> <win32u.dll>");
        return ExitCode::from(2);
    }
    let Some(preset) = find(&args[0]) else {
        eprintln!("unknown preset: {}", args[0]);
        return ExitCode::from(2);
    };
    let mut differences = 0;
    for (path, table) in [(&args[1], preset.nt), (&args[2], preset.win32k)] {
        let actual = match std::fs::read(path).map_err(|e| e.to_string()).and_then(|bytes| read_syscall_map(&bytes)) {
            Ok(map) => map,
            Err(error) => {
                eprintln!("{path}: {error}");
                return ExitCode::from(2);
            }
        };
        let expected: BTreeMap<_, _> = table.iter().map(|&(id, name)| (id, name)).collect();
        let mut changed = 0;
        for id in expected.keys().chain(actual.keys()).copied().collect::<std::collections::BTreeSet<_>>() {
            let wanted = expected.get(&id).copied();
            let found = actual.get(&id).map(String::as_str);
            if wanted != found {
                println!("0x{id:04X}\texpected={}\tactual={}", wanted.unwrap_or("<none>"), found.unwrap_or("<none>"));
                changed += 1;
            }
        }
        println!("{path}: expected={}, actual={}, differences={changed}", expected.len(), actual.len());
        differences += changed;
    }
    if differences == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

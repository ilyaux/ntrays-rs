//! Emits the existing PE parser's observed stubs; provenance is added by gen_syscall_presets.py.
use ntrays_core::syscall::read_syscall_map;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: capture_syscall_stubs <ntdll.dll> <win32u.dll>".into());
    }
    for (kind, path) in [("nt", &args[0]), ("win32k", &args[1])] {
        let map = read_syscall_map(&std::fs::read(path)?)?;
        for (id, name) in map {
            println!("{kind}\t{id}\t{name}");
        }
    }
    Ok(())
}

//! Prints a Driver Intelligence JSON file in canonical form (sorted, merged, pretty).
//!
//!     cargo run -q -p ntrays-core --example wdi_demo -- docs/src/wdi-overview.demo.json > out.json

use ntrays_core::wdi::DriverOverview;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: wdi_demo <overview.json>");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let overview = DriverOverview::from_json(&text).unwrap_or_else(|e| panic!("{path}: {e}"));
    println!("{}", overview.to_json());
}

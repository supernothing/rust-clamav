extern crate clamav;
extern crate tempfile;

use std::io::Write;

use clamav::scan_settings::ScanSettingsBuilder;
use clamav::{db, engine};
use tempfile::NamedTempFile;

mod common;

#[test]
fn scan_using_system_databases() {
    common::setup();

    let mut test_file: NamedTempFile = NamedTempFile::new().unwrap();
    // Per http://www.eicar.org/86-0-Intended-use.html
    write!(test_file, r"X5O!P%@AP[4\PZX54(P^)7CC)7}}$EICAR").unwrap();
    write!(test_file, r"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();
    test_file.flush().unwrap();

    let scan_settings = ScanSettingsBuilder::new().build();

    clamav::initialize().expect("initialize failed");
    let scanner = engine::Engine::new();
    scanner
        .load_databases(&db::default_directory())
        .expect("load failed");
    scanner.compile().expect("compile failed");

    let result = scanner
        .scan_file(test_file.path().to_str().unwrap(), &scan_settings)
        .unwrap();
    match result {
        engine::ScanResult::Virus(name) => assert_eq!(name, "Win.Test.EICAR_HDB-1"),
        _ => panic!("Expected test virust to be picked up as a virus"),
    }
}

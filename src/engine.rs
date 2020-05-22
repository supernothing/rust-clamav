use std::ffi::CStr;
use std::ffi::CString;
use std::ptr;
use std::str;

use error::ClamError;
use ffi;
use scan_settings::ScanSettings;

/// Stats of a loaded database
pub struct DatabaseStats {
    /// The total number of loaded signatures
    pub signature_count: u32,
}

pub enum ScanResult {
    /// Clean result
    Clean,
    /// Whitelisted result
    Whitelisted,
    /// Virus result, with detected name
    Virus(String),
}

/// Engine used for scanning files
pub struct Engine {
    handle: *mut ffi::cl_engine,
}

unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

fn map_scan_result(result: ffi::cl_error, virname: *const i8) -> Result<ScanResult, ClamError> {
    match result {
        ffi::cl_error::CL_CLEAN => Ok(ScanResult::Clean),
        ffi::cl_error::CL_BREAK => Ok(ScanResult::Whitelisted),
        ffi::cl_error::CL_VIRUS => {
            unsafe {
                let bytes = CStr::from_ptr(virname).to_bytes();
                let name = str::from_utf8(bytes).ok().unwrap_or_default().to_string();
                Ok(ScanResult::Virus(name))
            }
        }
        _ => Err(ClamError::new(result)),
    }
}

impl Engine {
    /// Initialises the engine
    pub fn new() -> Self {
        unsafe {
            let handle = ffi::cl_engine_new();
            Engine { handle }
        }
    }

    /// Compiles the loaded database definitions
    ///
    /// This function will compile the database definitions loaded
    /// in this engine using the [`load_database`] function.
    ///
    /// # Examples
    ///
    /// ```
    /// use clamav::{engine};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let scanner = engine::Engine::new();
    /// scanner.compile().expect("failed to compile");
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if compliation fails.
    /// The [`ClamError`] returned will contain the error code.
    ///
    /// [`ClamError`]: struct.ClamError.html
    pub fn compile(&self) -> Result<(), ClamError> {
        unsafe {
            let result = ffi::cl_engine_compile(self.handle);
            match result {
                ffi::cl_error::CL_SUCCESS => Ok(()),
                _ => Err(ClamError::new(result)),
            }
        }
    }

    /// Loads all of the definition databases (*.{cud, cvd}) in the specified directory.
    ///
    /// This function will load the definitions that can then be compiled with [`compile`].
    ///
    /// # Examples
    ///
    /// ```
    /// use clamav::{engine};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let scanner = engine::Engine::new();
    /// scanner.load_databases("test_data/database/").expect("failed to load");
    /// scanner.compile().expect("failed to compile");
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if compliation fails.
    /// The [`ClamError`] returned will contain the error code.
    ///
    /// [`ClamError`]: struct.ClamError.html
    pub fn load_databases(
        &self,
        database_directory_path: &str,
    ) -> Result<DatabaseStats, ClamError> {
        // consider the rust-ish builder pattern as it allows options to be specified
        let raw_path = CString::new(database_directory_path).unwrap();
        unsafe {
            let mut signature_count: u32 = 0;
            let result = ffi::cl_load(
                raw_path.as_ptr(),
                self.handle,
                &mut signature_count,
                ffi::CL_DB_STDOPT,
            );
            match result {
                ffi::cl_error::CL_SUCCESS => Ok(DatabaseStats { signature_count }),
                _ => Err(ClamError::new(result)),
            }
        }
    }

    /// Scans a file with the previously loaded and compiled definitions.
    ///
    /// This function will scan the given file with the the database definitions
    /// loaded and compiled.
    ///
    /// # Examples
    ///
    /// ```
    /// use clamav::{engine, engine::ScanResult, scan_settings::ScanSettings};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let scanner = engine::Engine::new();
    /// scanner.load_databases("test_data/database/").expect("failed to load");
    /// scanner.compile().expect("failed to compile");
    ///
    /// let settings: ScanSettings = Default::default();
    /// let hit = scanner.scan_file("test_data/files/good_file", &settings).expect("expected scan to succeed");
    ///
    /// match hit {
    ///     ScanResult::Virus(name) => println!("Virus {}", name),
    ///     ScanResult::Clean => println!("Clean"),
    ///     ScanResult::Whitelisted => println!("Whitelisted file")
    /// }
    /// ```
    ///
    /// ```
    /// use clamav::{engine, engine::ScanResult, scan_settings::ScanSettingsBuilder};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let scanner = engine::Engine::new();
    /// scanner.load_databases("test_data/database/").expect("failed to load");
    /// scanner.compile().expect("failed to compile");
    ///
    /// let settings = ScanSettingsBuilder::new()
    ///     .enable_pdf()
    ///     .block_broken_executables()
    ///     .build();
    /// println!("Using settings {}", settings);
    /// let hit = scanner.scan_file("test_data/files/good_file", &settings).expect("expected scan to succeed");
    ///
    /// match hit {
    ///     ScanResult::Virus(name) => println!("Virus {}", name),
    ///     ScanResult::Clean => println!("Clean"),
    ///     ScanResult::Whitelisted => println!("Whitelisted file")
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if the scan fails.
    /// The [`ClamError`] returned will contain the error code.
    ///
    /// [`ClamError`]: struct.ClamError.html
    pub fn scan_file(&self, path: &str, settings: &ScanSettings) -> Result<ScanResult, ClamError> {
        let raw_path = CString::new(path).unwrap();
        unsafe {
            let mut virname: *const i8 = ptr::null();
            let result = ffi::cl_scanfile(
                raw_path.as_ptr(),
                &mut virname,
                ptr::null_mut(),
                self.handle,
                settings.flags(),
            );
            map_scan_result(result, virname)
        }
    }

    /// Scans a descriptor with the previously loaded and compiled definitions.
    ///
    /// This function will scan the given descriptor with the the database definitions
    /// loaded and compiled.
    pub fn scan_descriptor(&self, descriptor: i32, settings: &ScanSettings) -> Result<ScanResult, ClamError> {
        unsafe {
            let mut virname: *const i8 = ptr::null();
            let result = ffi::cl_scandesc(
                descriptor,
                &mut virname,
                ptr::null_mut(),
                self.handle,
                settings.flags(),
            );
            map_scan_result(result, virname)
        }
    }

}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            ffi::cl_engine_free(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    const TEST_DATABASES_PATH: &'static str = "test_data/database/";
    const EXAMPLE_DATABASE_PATH: &'static str = "test_data/database/example.cud";
    const GOOD_FILE_PATH: &'static str = "test_data/files/good_file";
    const NAUGHTY_FILE_PATH: &'static str = "test_data/files/naughty_file";

    #[test]
    fn compile_empty_engine_success() {
        ::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        assert!(scanner.compile().is_ok(), "compile should succeed");
    }

    #[test]
    fn load_databases_success() {
        ::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        let result = scanner.load_databases(TEST_DATABASES_PATH);
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[test]
    fn load_databases_with_file_success() {
        ::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        let result = scanner.load_databases(EXAMPLE_DATABASE_PATH);
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[test]
    fn load_databases_fake_path_fails() {
        ::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        assert!(
            scanner.load_databases("/dev/null").is_err(),
            "should fail to load invalid databases"
        );
    }

    #[test]
    fn scan_naughty_file_matches() {
        ::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        scanner
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        scanner.compile().expect("failed to compile");
        let settings: ScanSettings = Default::default();
        let result = scanner.scan_file(NAUGHTY_FILE_PATH, &settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Virus(name) => {
                assert_eq!(name, "naughty_file.UNOFFICIAL");
            }
            _ => panic!("should have matched as a virus"),
        }
    }

    #[test]
    fn scan_good_file_success() {
        ::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        scanner
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        scanner.compile().expect("failed to compile");
        let settings: ScanSettings = Default::default();
        let result = scanner.scan_file(GOOD_FILE_PATH, &settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Clean => {}
            _ => panic!("should have matched as a virus"),
        }
    }
/*
    #[test]
    fn scan_naughty_fd_matches() {
        ::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        scanner
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        scanner.compile().expect("failed to compile");
        let settings: ScanSettings = Default::default();
        let file = File::open(NAUGHTY_FILE_PATH).unwrap();
        let result = scanner.scan_descriptor(file.as_raw_fd(), &settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Virus(name) => {
                assert_eq!(name, "naughty_file.UNOFFICIAL");
            }
            _ => panic!("should have matched as a virus"),
        }
    }

    #[test]
    fn scan_good_fd_success() {
        ::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        scanner
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        scanner.compile().expect("failed to compile");
        let settings: ScanSettings = Default::default();
        let file = File::open(GOOD_FILE_PATH).unwrap();
        let result = scanner.scan_descriptor(file.as_raw_fd(), &settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Clean => {}
            _ => panic!("should have matched as a virus"),
        }
    }

 */
}

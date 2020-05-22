#![allow(dead_code)]

use std::fmt;

use ffi;

pub struct ScanSettings {
    settings: ffi::cl_scan_options,
}

impl ScanSettings {
    pub fn flags(&self) -> &ffi::cl_scan_options {
        &self.settings
    }
}

impl Default for ScanSettings {
    /// Returns the defualt scan settings per libclamav recommendations
    fn default() -> ScanSettings {
        ScanSettings {
            settings: ffi::CL_SCAN_DEFAULT_OPT.clone(),
        }
    }
}

impl fmt::Display for ScanSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = String::new();

        // raw isn't a bitflag, it means "no special handling"
        if self.settings.general | self.settings.heuristic | self.settings.dev | self.settings.mail
            | self.settings.parse == 0 {
            flags.push_str("CL_SCAN_RAW ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_ARCHIVE == ffi::CL_SCAN_ARCHIVE {
            flags.push_str("CL_SCAN_PARSE_ARCHIVE ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_MAIL == ffi::CL_SCAN_MAIL {
            flags.push_str("CL_SCAN_PARSE_MAIL ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_OLE2 == ffi::CL_SCAN_PARSE_OLE2 {
            flags.push_str("CL_SCAN_PARSE_OLE2 ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE == ffi::CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE {
            flags.push_str("CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_ENCRYPTED_DOC == ffi::CL_SCAN_HEURISTIC_ENCRYPTED_DOC {
            flags.push_str("CL_SCAN_HEURISTIC_ENCRYPTED_DOC ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_HTML == ffi::CL_SCAN_PARSE_HTML {
            flags.push_str("CL_SCAN_PARSE_HTML ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_PE == ffi::CL_SCAN_PARSE_PE {
            flags.push_str("CL_SCAN_PARSE_PE ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_BROKEN == ffi::CL_SCAN_HEURISTIC_BROKEN {
            flags.push_str("CL_SCAN_HEURISTIC_BROKEN ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_EXCEEDS_MAX == ffi::CL_SCAN_HEURISTIC_EXCEEDS_MAX {
            flags.push_str("CL_SCAN_HEURISTIC_EXCEEDS_MAX ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH == ffi::CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH {
            flags.push_str("CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_PHISHING_CLOAK == ffi::CL_SCAN_HEURISTIC_PHISHING_CLOAK {
            flags.push_str("CL_SCAN_HEURISTIC_PHISHING_CLOAK ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_ELF == ffi::CL_SCAN_PARSE_ELF {
            flags.push_str("CL_SCAN_PARSE_ELF ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_PDF == ffi::CL_SCAN_PARSE_PDF {
            flags.push_str("CL_SCAN_PARSE_PDF ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_STRUCTURED == ffi::CL_SCAN_HEURISTIC_STRUCTURED {
            flags.push_str("CL_SCAN_HEURISTIC_STRUCTURED ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL == ffi::CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL
        {
            flags.push_str("CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED
            == ffi::CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED
        {
            flags.push_str("CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED ");
        }
        if self.settings.mail & ffi::CL_SCAN_MAIL_PARTIAL_MESSAGE == ffi::CL_SCAN_MAIL_PARTIAL_MESSAGE {
            flags.push_str("CL_SCAN_MAIL_PARTIAL_MESSAGE ");
        }
        if self.settings.general & ffi::CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE == ffi::CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE {
            flags.push_str("CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_MACROS == ffi::CL_SCAN_HEURISTIC_MACROS {
            flags.push_str("CL_SCAN_HEURISTIC_MACROS ");
        }
        if self.settings.general & ffi::CL_SCAN_GENERAL_ALLMATCHES == ffi::CL_SCAN_GENERAL_ALLMATCHES {
            flags.push_str("CL_SCAN_GENERAL_ALLMATCHES ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_SWF == ffi::CL_SCAN_PARSE_SWF {
            flags.push_str("CL_SCAN_PARSE_SWF ");
        }
        if self.settings.heuristic & ffi::CL_SCAN_HEURISTIC_PARTITION_INTXN == ffi::CL_SCAN_HEURISTIC_PARTITION_INTXN {
            flags.push_str("CL_SCAN_HEURISTIC_PARTITION_INTXN ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_XMLDOCS == ffi::CL_SCAN_PARSE_XMLDOCS {
            flags.push_str("CL_SCAN_PARSE_XMLDOCS ");
        }
        if self.settings.parse & ffi::CL_SCAN_PARSE_HWP3 == ffi::CL_SCAN_PARSE_HWP3 {
            flags.push_str("CL_SCAN_PARSE_HWP3 ");
        }
        if self.settings.dev & ffi::CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO == ffi::CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO {
            flags.push_str("CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO ");
        }
        if self.settings.dev & ffi::CL_SCAN_DEV_COLLECT_SHA == ffi::CL_SCAN_DEV_COLLECT_SHA {
            flags.push_str("CL_SCAN_DEV_COLLECT_SHA ");
        }
        write!(f, "{:#X} {:#X} {:#X} {:#X} {:#X}: {}", self.settings.general, self.settings.parse,
               self.settings.heuristic, self.settings.mail, self.settings.dev, flags.trim_end())
    }
}

pub struct ScanSettingsBuilder {
    current: ffi::cl_scan_options,
}

impl ScanSettingsBuilder {
    pub fn new() -> Self {
        ScanSettingsBuilder {
            current: ffi::CL_SCAN_DEFAULT_OPT.clone(),
        }
    }

    pub fn build(&self) -> ScanSettings {
        ScanSettings {
            settings: self.current.clone(),
        }
    }

    /// Disable support for special files.
    pub fn clear(&mut self) -> &mut Self {
        self.current = ffi::CL_SCAN_RAW_OPT;
        self
    }

    /// Set a flag explicitly
    /// TODO make individual with_flag for each field
    /*pub fn with_flag(&mut self, flag: u32) -> &mut Self {
        self.current |= flag;
        self
    }*/

    /// Enable transparent scanning of various archive formats.
    pub fn enable_archive(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_ARCHIVE;
        self
    }

    /// Enable support for mail files.
    pub fn enable_mail(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_MAIL;
        self
    }

    /// Enable support for OLE2 containers (used by MS Office and .msi files).
    pub fn enable_ole2(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_OLE2;
        self
    }

    /// With this flag the library will mark encrypted archives as viruses (Encrypted.Zip, Encrypted.RAR).
    pub fn block_encrypted(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
        self
    }

    /// Enable HTML normalisation (including ScrEnc decryption).
    pub fn enable_html(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_HTML;
        self
    }

    /// Enable deep scanning of Portable Executable files and allows libclamav to unpack executables compressed with run-time unpackers.
    pub fn enable_pe(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_PE;
        self
    }

    /// Try to detect broken executables and mark them as Broken.Executable.
    pub fn block_broken_executables(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_BROKEN;
        self
    }

    ///  Mark archives as viruses if maxfiles, maxfilesize, or maxreclevel limit is reached.
    pub fn block_max_limit(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_EXCEEDS_MAX;
        self
    }

    /// Enable algorithmic detection of viruses.
    pub fn enable_algorithmic(&mut self) -> &mut Self {
        self.current.general |= ffi::CL_SCAN_GENERAL_HEURISTICS;
        self
    }

    /// Enable phishing module: always block SSL mismatches in URLs.
    pub fn enable_phishing_blockssl(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH;
        self
    }

    /// Enable phishing module: always block cloaked URLs.
    pub fn enable_phishing_blockcloak(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_PHISHING_CLOAK;
        self
    }

    /// Enable support for ELF files.
    pub fn enable_elf(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_ELF;
        self
    }

    /// Enable scanning within PDF files.
    pub fn enable_pdf(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_PDF;
        self
    }

    /// Enable the DLP module which scans for credit card and SSN numbers.
    pub fn enable_structured(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_STRUCTURED;
        self
    }

    /// Enable search for SSNs formatted as xx-yy-zzzz.
    pub fn enable_structured_ssn_normal(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL;
        self
    }

    /// Enable search for SSNs formatted as xxyyzzzz.
    pub fn enable_structured_ssn_stripped(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED;
        self
    }

    /// Enable scanning of RFC1341 messages split over many emails.
    ///
    /// You will need to periodically clean up $TemporaryDirectory/clamav-partial directory.
    pub fn enable_partial_message(&mut self) -> &mut Self {
        self.current.mail |= ffi::CL_SCAN_MAIL_PARTIAL_MESSAGE;
        self
    }

    /// Allow heuristic match to take precedence. When enabled, if a heuristic scan (such
    /// as phishingScan) detects a possible virus/phish it will stop scan immediately.
    ///
    /// Recommended, saves CPU scan-time. When disabled, virus/phish detected by heuristic
    /// scans will be reported only at the end of a scan. If an archive contains both a
    /// heuristically detected virus/phishing, and a real malware, the real malware will be
    /// reported.
    pub fn enable_heuristic_precedence(&mut self) -> &mut Self {
        self.current.general |= ffi::CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
        self
    }

    /// OLE2 containers, which contain VBA macros will be marked infected (Heuris-tics.OLE2.ContainsMacros).
    pub fn block_macros(&mut self) -> &mut Self {
        self.current.heuristic |= ffi::CL_SCAN_HEURISTIC_MACROS;
        self
    }

    /// Enable scanning within SWF files, notably compressed SWF.
    pub fn enable_swf(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_SWF;
        self
    }

    /// Enable scanning of XML docs.
    pub fn enable_xmldocs(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_XMLDOCS;
        self
    }

    /// Enable scanning of HWP3 files.
    pub fn enable_hwp3(&mut self) -> &mut Self {
        self.current.parse |= ffi::CL_SCAN_PARSE_HWP3;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_to_standard_opts() {
        let settings = ScanSettingsBuilder::new().build();
        let default = ffi::CL_SCAN_DEFAULT_OPT.clone();
        assert_eq!(settings.settings.general | settings.settings.dev |
                   settings.settings.mail | settings.settings.heuristic | settings.settings.parse,
                   default.general|default.dev|default.mail|default.heuristic|default.parse);
    }

    #[test]
    fn builder_clear_success() {
        let settings = ScanSettingsBuilder::new().clear().build();
        assert_eq!(settings.settings.general | settings.settings.dev |
                       settings.settings.mail | settings.settings.heuristic | settings.settings.parse, 0);
    }

    #[test]
    fn builder_just_pdf_success() {
        let settings = ScanSettingsBuilder::new().clear().enable_pdf().build();
        assert_eq!(settings.settings.parse, ffi::CL_SCAN_PARSE_PDF);
    }

    #[test]
    fn builder_normal_files_success() {
        let settings = ScanSettingsBuilder::new()
            .clear()
            .enable_pdf()
            .enable_html()
            .enable_pe()
            .build();
        assert_eq!(
            settings.settings.parse,
            ffi::CL_SCAN_PARSE_PDF | ffi::CL_SCAN_PARSE_HTML | ffi::CL_SCAN_PARSE_PE
        );
    }

    #[test]
    fn builder_all_success() {
        let settings = ScanSettingsBuilder::new()
            .clear()
            .enable_algorithmic()
            .enable_archive()
            .enable_elf()
            .enable_heuristic_precedence()
            .enable_html()
            .enable_hwp3()
            .enable_mail()
            .enable_ole2()
            .enable_partial_message()
            .enable_pdf()
            .enable_pe()
            .enable_phishing_blockcloak()
            .enable_phishing_blockssl()
            .enable_structured()
            .enable_structured_ssn_normal()
            .enable_structured_ssn_stripped()
            .enable_swf()
            .enable_xmldocs()
            .block_broken_executables()
            .block_encrypted()
            .block_macros()
            .block_max_limit()
            .build();
        assert_eq!(settings.settings.parse, ffi::CL_SCAN_PARSE_ELF| ffi::CL_SCAN_PARSE_PDF |
            ffi::CL_SCAN_PARSE_ARCHIVE | ffi::CL_SCAN_PARSE_MAIL | ffi::CL_SCAN_PARSE_OLE2 |
            ffi::CL_SCAN_PARSE_HTML | ffi::CL_SCAN_PARSE_PE | ffi::CL_SCAN_PARSE_SWF |
            ffi::CL_SCAN_PARSE_XMLDOCS | ffi::CL_SCAN_PARSE_HWP3);
        assert_eq!(settings.settings.general, ffi::CL_SCAN_GENERAL_HEURISTICS |
            ffi::CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE);
        assert_eq!(settings.settings.heuristic, ffi::CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE |
            ffi::CL_SCAN_HEURISTIC_BROKEN | ffi::CL_SCAN_HEURISTIC_EXCEEDS_MAX |
            ffi::CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH | ffi::CL_SCAN_HEURISTIC_PHISHING_CLOAK |
            ffi::CL_SCAN_HEURISTIC_STRUCTURED | ffi::CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL |
            ffi::CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED | ffi::CL_SCAN_HEURISTIC_MACROS);
        assert_eq!(settings.settings.mail, ffi::CL_SCAN_MAIL_PARTIAL_MESSAGE);
    }

    #[test]
    fn display_settings_standard_options_success() {
        let string_settings = ScanSettings {
            settings: ffi::CL_SCAN_DEFAULT_OPT,
        }.to_string();
        assert!(string_settings.contains("CL_SCAN_PARSE_ARCHIVE"));
        assert!(string_settings.contains("CL_SCAN_PARSE_OLE2"));
        assert!(string_settings.contains("CL_SCAN_PARSE_PDF"));
        assert!(string_settings.contains("CL_SCAN_PARSE_HTML"));
        assert!(string_settings.contains("CL_SCAN_PARSE_PE"));
        assert!(string_settings.contains("CL_SCAN_PARSE_ELF"));
        assert!(string_settings.contains("CL_SCAN_PARSE_SWF"));
    }

    #[test]
    fn settings_default_to_standard() {
        let settings: ScanSettings = Default::default();
        let default = ffi::CL_SCAN_DEFAULT_OPT.clone();
        assert_eq!(settings.settings.general | settings.settings.dev |
                       settings.settings.mail | settings.settings.heuristic | settings.settings.parse,
                   default.general|default.dev|default.mail|default.heuristic|default.parse);
    }
}

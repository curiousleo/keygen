use std::io::{BufRead, Cursor, Write};
use std::process::{Command, Stdio};

const NAME: &str = "Clark Kent";
const ADDRESS: &str = "kent@dailyplanet.com";
const PASSWORD: &str = "1-aM-k4l-3L";

#[test]
fn integration() -> std::io::Result<()> {
    // Setup
    let dir = tempfile::tempdir()?;
    let key_path = dir.path().join("key");
    let rev_path = dir.path().join("rev");

    // Run keygen
    let mut keygen = test_bin::get_test_bin("keygen")
        .args(&[&key_path, &rev_path])
        .stdin(Stdio::piped())
        .spawn()?;
    {
        let stdin = keygen.stdin.as_mut().unwrap();
        write!(stdin, "{}\n{}\n{}", NAME, ADDRESS, PASSWORD)?;
    }
    let status = keygen.wait()?;

    // Basic keygen assertions
    assert!(status.success(), "keygen exit status: {}", status);
    assert!(key_path.is_file(), "keygen key file");
    assert!(rev_path.is_file(), "keygen revocation certificate file");

    // Analyse generated key with gpg, inspired by https://stackoverflow.com/a/22147722
    let gpg_show_key = Command::new("gpg")
        .args(&[
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            key_path.to_str().unwrap(),
        ])
        .output()?;
    {
        let status = gpg_show_key.status;
        assert!(status.success(), "gpg exit status: {}", status);
    }

    // Parse gpg output as a list of records
    let records: Vec<GPGRecord> = gpg_show_key
        .stdout
        .lines()
        .map(|l| {
            GPGRecord::new(
                Cursor::new(l.unwrap())
                    .split(b':')
                    .map(|s| String::from_utf8(s.unwrap()).unwrap())
                    .collect(),
            )
        })
        .collect();

    // Master key assertions
    {
        let master_keys: Vec<&GPGRecord> = records
            .iter()
            .filter(|r| r.keytype() == Some(KeyType::Priv))
            .collect();
        assert_eq!(1, master_keys.len(), "must have exactly one master key");

        let master_key = master_keys[0];
        assert_eq!(
            PKAlgo::RSAEncryptOrSign,
            master_key.pk_algo().unwrap(),
            "wrong algorithm"
        );
        assert_eq!(3072, master_key.keylen().unwrap(), "wrong key length");
        assert!(!master_key.has_expiration(), "must not expire");

        let (own, whole) = master_key.capability();
        assert_eq!(Capability::certify_only(), own, "should only certify");
        assert_eq!(
            Capability {
                encrypt: true,
                sign: true,
                certify: true,
                auth: true,
                unknown: false,
            },
            whole,
            "should have all capabilities"
        );
    }

    // Subkey assertions
    {
        let sub_keys: Vec<&GPGRecord> = records
            .iter()
            .filter(|r| r.keytype() == Some(KeyType::PrivSub))
            .collect();
        assert_eq!(3, sub_keys.len(), "must have exactly three private subkeys");

        sub_keys.iter().for_each(|r| {
            assert_eq!(3072, r.keylen().unwrap(), "wrong key length");
            assert_eq!(
                PKAlgo::RSAEncryptOrSign,
                r.pk_algo().unwrap(),
                "wrong algorithm"
            );
            assert!(!r.has_expiration(), "must not expire")
        });

        let own_capabilities: Vec<Capability> =
            sub_keys.into_iter().map(|r| r.capability().0).collect();
        let expected_capabilities = vec![
            Capability::sign_only(),
            Capability::encrypt_only(),
            Capability::auth_only(),
        ];
        assert!(
            expected_capabilities
                .iter()
                .all(|e| own_capabilities.iter().find(|&c| e == c).is_some()),
            "must have signing, encryption and authentication subkey"
        );
    }

    Ok(())
}

struct GPGRecord {
    fields: Vec<String>,
}

#[derive(PartialEq)]
enum KeyType {
    Pub,
    PubSub,
    Priv,
    PrivSub,
}

#[derive(Debug, PartialEq)]
struct Capability {
    encrypt: bool,
    sign: bool,
    certify: bool,
    auth: bool,
    unknown: bool,
}

impl Default for Capability {
    fn default() -> Capability {
        Capability {
            encrypt: false,
            sign: false,
            certify: false,
            auth: false,
            unknown: false,
        }
    }
}

impl Capability {
    fn encrypt_only() -> Self {
        let mut cap = Capability::default();
        cap.encrypt = true;
        cap
    }

    fn sign_only() -> Self {
        let mut cap = Capability::default();
        cap.sign = true;
        cap
    }

    fn certify_only() -> Self {
        let mut cap = Capability::default();
        cap.certify = true;
        cap
    }

    fn auth_only() -> Self {
        let mut cap = Capability::default();
        cap.auth = true;
        cap
    }
}

#[derive(Debug, PartialEq)]
enum PKAlgo {
    RSAEncryptOrSign = 1,
    RSAEncrypt = 2,
    RSASign = 3,
    Other,
}

impl From<usize> for PKAlgo {
    fn from(u: usize) -> PKAlgo {
        match u {
            1 => PKAlgo::RSAEncryptOrSign,
            2 => PKAlgo::RSAEncrypt,
            3 => PKAlgo::RSASign,
            _ => PKAlgo::Other,
        }
    }
}

// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
impl GPGRecord {
    fn new(fields: Vec<String>) -> Self {
        GPGRecord { fields }
    }

    fn keytype(&self) -> Option<KeyType> {
        match self.fields[0].as_str() {
            "pub" => Some(KeyType::Pub),
            "sub" => Some(KeyType::PubSub),
            "sec" => Some(KeyType::Priv),
            "ssb" => Some(KeyType::PrivSub),
            _ => None,
        }
    }

    fn keylen(&self) -> Option<usize> {
        let field = &self.fields[2];
        if field.is_empty() {
            None
        } else {
            Some(usize::from_str_radix(field, 10).unwrap())
        }
    }

    fn pk_algo(&self) -> Option<PKAlgo> {
        let field = &self.fields[3];
        if field.is_empty() {
            None
        } else {
            Some(PKAlgo::from(usize::from_str_radix(field, 10).unwrap()))
        }
    }

    fn has_expiration(&self) -> bool {
        !self.fields[6].is_empty()
    }

    fn user_id(&self) -> String {
        self.fields[9].clone()
    }

    fn capability(&self) -> (Capability, Capability) {
        let mut own = Capability::default();
        let mut whole = Capability::default();

        self.fields[11].as_str().chars().for_each(|c| match c {
            'e' => own.encrypt = true,
            's' => own.sign = true,
            'c' => own.certify = true,
            'a' => own.auth = true,
            '?' => own.unknown = true,
            'E' => whole.encrypt = true,
            'S' => whole.sign = true,
            'C' => whole.certify = true,
            'A' => whole.auth = true,
            _ => panic!("undefined capability: {}", c),
        });

        (own, whole)
    }
}

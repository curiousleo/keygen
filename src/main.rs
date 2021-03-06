//! keygen <key file> <revocation certificate file>
//!
//! Generates an OpenPGP keypair and writes it and a corresponding revocation certificate to the
//! paths specified as command line arguments.
//!
//! The 4096-bit RSA keypair contains:
//! - a master key that can only certify
//! - a subkey that can only sign
//! - a subkey that can only encrypt
//! - a subkey that can only authenticate

use atty::Stream;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::{
    crypto::Password,
    packet::{Signature, UserID},
    tpk::{CipherSuite, TPKBuilder, TPK},
    types::KeyFlags,
    Packet,
};
use std::fs::File;
use std::io::{stdin, stdout, Write};
use std::time::Duration;
use termion::input::TermRead;

fn main() -> sequoia_openpgp::Result<()> {
    let (key_path, rev_path) = {
        let args: Vec<String> = std::env::args().collect();
        if args.len() != 3 {
            panic!("Usage: keygen <key file> <revocation certificate file>");
        }
        (args[1].clone(), args[2].clone())
    };

    let user_id = {
        let name = prompt("Name:     ")?;
        let address = prompt("E-mail:   ")?;
        UserID::from_address(Some(name), /* comment */ None, address)?
    };

    let password = {
        let password = prompt_passwd("Password: ")?;
        Password::from(password.into_bytes())
    };

    if is_interactive() {
        println!("Generating key ...");
    }
    let (tpk, revocation_sig) = generate_key(user_id, password)?;

    let mut key_file = File::create(key_path)?;
    tpk.as_tsk().serialize(&mut key_file).unwrap();

    let mut rev_file = File::create(rev_path)?;
    Packet::from(revocation_sig)
        .serialize(&mut rev_file)
        .unwrap();

    Ok(())
}

fn generate_key(user_id: UserID, password: Password) -> sequoia_openpgp::Result<(TPK, Signature)> {
    let certify_only: KeyFlags = KeyFlags::empty().set_certify(true);
    let sign_only: KeyFlags = KeyFlags::empty().set_sign(true);
    let encrypt_only: KeyFlags = KeyFlags::empty()
        .set_encrypt_for_transport(true)
        .set_encrypt_at_rest(true);
    let auth_only: KeyFlags = KeyFlags::empty().set_authenticate(true);
    let leap_year = Duration::new(366 * 24 * 60 * 60, 0);

    TPKBuilder::new()
        // RSA4096 with SHA512 and AES256
        .set_cipher_suite(CipherSuite::RSA4k)
        .primary_keyflags(certify_only)
        .set_expiration(None)
        .set_password(Some(password))
        .add_userid(user_id)
        .add_subkey(sign_only, Some(leap_year))
        .add_subkey(encrypt_only, Some(leap_year))
        .add_subkey(auth_only, Some(leap_year))
        .generate()
}

fn prompt(query: &str) -> std::io::Result<String> {
    if is_interactive() {
        print!("{}", query);
        stdout().flush()?;
    }

    let mut input = String::new();
    stdin().read_line(&mut input)?;

    // Remove newline at the end of input
    input.pop();

    Ok(input)
}

fn prompt_passwd(query: &str) -> std::io::Result<String> {
    if !is_interactive() {
        return prompt(query);
    }

    print!("{}", query);
    stdout().flush()?;

    let mut writer = vec![];
    let password = stdin().read_passwd(&mut writer)?.unwrap();
    println!();

    Ok(password)
}

fn is_interactive() -> bool {
    atty::is(Stream::Stdin)
}

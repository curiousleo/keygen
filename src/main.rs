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

use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::{
    constants::KeyFlags,
    crypto::Password,
    packet::{Signature, UserID},
    tpk::{CipherSuite, TPKBuilder, TPK},
    Packet,
};
use std::fs::File;
use std::io::{stdin, stdout, Write};
use termion::input::TermRead;

fn main() -> sequoia_openpgp::Result<()> {
    let (key_path, rev_path, interactive) = {
        let args: Vec<String> = std::env::args().collect();
        if args.len() == 3 {
            (
                args[1].clone(),
                args[2].clone(),
                /* interactive */ true,
            )
        } else if args.len() == 4 && args[1] == "--noninteractive" {
            (
                args[2].clone(),
                args[3].clone(),
                /* interactive */ false,
            )
        } else {
            panic!("Usage: keygen [--noninteractive] <key file> <revocation certificate file>");
        }
    };

    let user_id = {
        let name = prompt("Name:     ", interactive)?;
        let address = prompt("E-mail:   ", interactive)?;
        UserID::from_address(Some(name), /* comment */ None, address)?
    };

    let password = {
        let password = prompt_passwd("Password: ", interactive)?;
        Password::from(password.into_bytes())
    };

    println!("Generating key ...");
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

    TPKBuilder::new()
        // RSA4096 with SHA512 and AES256
        .set_cipher_suite(CipherSuite::RSA4k)
        .primary_keyflags(certify_only)
        .set_expiration(None)
        .set_password(Some(password))
        .add_userid(user_id)
        .add_subkey(sign_only)
        .add_subkey(encrypt_only)
        .add_subkey(auth_only)
        .generate()
}

fn prompt(query: &str, interactive: bool) -> std::io::Result<String> {
    if interactive {
        print!("{}", query);
        stdout().flush()?;
    }

    let mut input = String::new();
    stdin().read_line(&mut input)?;

    // Remove newline at the end of input
    input.pop();

    Ok(input)
}

fn prompt_passwd(query: &str, interactive: bool) -> std::io::Result<String> {
    if !interactive {
        return prompt(query, interactive);
    }

    print!("{}", query);
    stdout().flush()?;

    let mut writer = vec![];
    let password = stdin().read_passwd(&mut writer)?.unwrap();
    println!();

    Ok(password)
}

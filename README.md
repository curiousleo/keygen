# keygen

Generates GPG keys as described in
[drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md),
specifically the [Master
key](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md#master-key)
and
[Sub-keys](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md#sub-keys)
sections.

## Caveats

This project is still under construction. The following caveats apply:

- `keygen` currently does not set **expiration dates** for the subkeys as
  recommended in the guide. This is because the underlying library [does not
  support setting the expiration date
  separately](https://gitlab.com/sequoia-pgp/sequoia/issues/366) for the master
  (which should not have an expiration date) and subkeys (which should).
- `keygen` generates RSA keys with a key length of **3072 bit instead of the
  4096 bit** recommended in the guide. This is because the underlying library
  [does not currently support 4096-bit RSA
  keys](https://gitlab.com/sequoia-pgp/sequoia/issues/367).
- `keygen` does not currently [write the **revocation certificate** to a
  file](https://gitlab.com/sequoia-pgp/sequoia/issues/368), you need to
  generate it using `gpg`.

## What is this good for?

Getting started with GPG is a lot of work. I found the key generation procedure
in guides like [this
one](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md)
a particularly manual and thus error-prone part of the process. So I wrote this
program to automate it.

## What does `keygen` do?

Given a name, address and password of your choosing, `keygen` generates a
3072-bit RSA GPG key with the following structure:

- a master key that can only _certify_;
- a subkey that can only _sign_;
- a subkey that can only _encrypt_;
- a subkey that can only _authenticate_.

## Why should I trust you?

Don't. Verify the generated key!

Check the
[Verify](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md#sub-keys)
section of @drduh's guide to see what the key should look like. Then run the
following to check your key without importing it:

```console
$ gpg --import-options show-only --import <keyfile>
```

When you're satisfied, import the key as follows:

```console
$ gpg --import <keyfile>
```

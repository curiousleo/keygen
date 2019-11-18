# keygen

[![Build Status](https://api.cirrus-ci.com/github/curiousleo/keygen.svg?branch=master)](https://cirrus-ci.com/github/curiousleo/keygen)

Generates GPG keys as described in
[drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md),
specifically the [Master
key](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md#master-key)
and
[Sub-keys](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md#sub-keys)
sections.

## Caveats

This project is still under construction. The following caveat applies:

- `keygen` currently does not set **expiration dates** for the subkeys as
  recommended in the guide. This is because the underlying library does not
  currently support setting the expiration date separately for the master
  (which should not have an expiration date) and subkeys (which should).
  [Upstream ticket.](https://gitlab.com/sequoia-pgp/sequoia/issues/366)

## What is this good for?

Getting started with GPG is a lot of work. I found the key generation procedure
in guides like [this
one](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md)
a particularly manual and thus error-prone part of the process. So I wrote this
program to automate it.

## What does `keygen` do?

Given a name, address and password of your choosing, `keygen` generates a
4096-bit RSA GPG key with the following structure:

- a master key that can only _certify_;
- a subkey that can only _sign_;
- a subkey that can only _encrypt_;
- a subkey that can only _authenticate_.

In addition, `keygen` generates a revocation certificate for the master key.

## Why should I trust you?

Don't. Verify the generated key and certificate!

Check the
[Verify](https://github.com/drduh/YubiKey-Guide/blob/010accf86451eca0a933c70b9b74b822796d78e3/README.md#sub-keys)
section of @drduh's guide to see what the key should look like. Then run the
following to check your key without importing it:

```console
$ gpg --import-options show-only --import <key file or certificate file>
```

When you're satisfied, import the key as follows. Do _not_ import the
revocation certificate at this point - doing so will revoke the key you just
created!

```console
$ gpg --import <key file>
```

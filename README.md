# Ár Rúin -- Our Secrets

A local encrypted secrets file manager.

## How it Works

Secrets are stored in a local file that is GPG encrypted. There are standard CRUD methods for password management, using a single line format. It is also possible to write and manually edit a cleartext copy of the secrets file, before creating a new encrypted version then shredding the cleartext.

The password format is a simple space separated line termianated by a new line: `site user password (old password)`.

Other secrets may also be added in a schemaless and multiline format but they won't be managed by the CRUD methods.

The default name of the encrypted secrets file is db.asc

## Hardening

Decrypted secrets are handled with the following precautions:

* The `edit` command's temporary cleartext file is always shredded on the way out -- including on Ctrl-C or an editor error, not just on a clean run.
* `edit` refuses to run if `shred` is not on `PATH`; a failed shred is reported as a warning rather than silently ignored.
* Decrypted buffers are zeroed and `mlock`ed against swap while in use, for every command, not just `edit`.
* The process disables core dumps and marks itself non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`) -- the same measures GnuPG's `gpg-agent` and OpenSSH's `ssh-agent` take for processes holding key material.

These are best-effort protections, not guarantees -- see the comments in `gpg.go` and `main.go` for their specific limitations.

## Requirements

* Linux
* GNUPG
* `shred` (GNU coreutils)
* Existing GPG keys -- arruin does not manage keys

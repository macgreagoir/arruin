# Ár Rúin -- Our Secrets

A local encrypted secrets file manager.

## How it Works

Secrets are stored in a local file that is GPG encrypted. There are standard CRUD methods for password management, using a single line format. It is also possible to decrypt into an in-memory file and manually edit it with `$EDITOR`, before creating a new encrypted version.

The password format is a simple space separated line termianated by a new line: `site user password (old password)`.

Other secrets may also be added in a schemaless and multiline format but they won't be managed by the CRUD methods.

The default name of the encrypted secrets file is db.asc

## Hardening

Decrypted secrets are handled with the following precautions:

* The `edit` command hands decrypted secrets to `$EDITOR` through an anonymous, memory-only file (`memfd_create`) rather than a real temporary file -- it has no path on any filesystem, so there's nothing to leave behind or shred, and its memory is reclaimed unconditionally when the process exits, even on a crash or Ctrl-C.
* Decrypted buffers are zeroed and `mlock`ed against swap while in use, for every command, not just `edit`. The in-memory file's own backing pages are deliberately *not* locked this way -- investigated and found not practically achievable on Linux; see `newMemFile`'s comment in `gpg.go` for why.
* The process disables core dumps and marks itself non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`) -- the same measures GnuPG's `gpg-agent` and OpenSSH's `ssh-agent` take for processes holding key material.

These are best-effort protections, not guarantees -- see the comments in `gpg.go` and `main.go` for their specific limitations.

## Requirements

* Linux
* GNUPG
* Existing GPG keys -- arruin does not manage keys

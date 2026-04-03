# Ár Rúin -- Our Secrets

A local encrypted secrets file manager.

## How it Works

Secrets are stored in a local file that is GPG encrypted. There are standard CRUD methods for password management, using a single line format. It is also possible to write and manually edit a cleartext copy of the secrets file, before creating a new encrypted version then shredding the cleartext.

The password format is a simple space separated line termianated by a new line: `site user password (old password)`.

Other secrets may also be added in a schemaless and multiline format but they won't be managed by the CRUD methods.

The default name of the encrypted secrets file is db.asc

## Requirements

* Linux
* GNUPG
* Existing GPG keys -- arruin does not manage keys

# Verifying OptraSight Releases

This file explains how to verify BatchOne release artifacts before running them locally.

## Signing Key

Release artifacts are signed with the OptraSight BatchOne release key stored in this repository:

```text
signing/keys/kensho-public.asc
```

Key identity:

```text
Kensho (Kensho@CEP Code Signing) <kensho@chillethicalpeople.com>
```

Expected fingerprint:

```text
9A48 5697 9127 52B9 4287 8895 D068 0F89 CD74 8B8B
```

Public key file SHA-256:

```text
951d49b52a3254e6f163ad021505016f00eb8d0ec6cafd416820ffb1d4420cba  signing/keys/kensho-public.asc
```

## Import The Public Key

From the repository root:

```bash
gpg --import signing/keys/kensho-public.asc
gpg --fingerprint kensho@chillethicalpeople.com
```

Confirm the displayed fingerprint exactly matches:

```text
9A48 5697 9127 52B9 4287 8895 D068 0F89 CD74 8B8B
```

## Verify A Source Archive

For a release archive such as:

```text
optrasight-batchone-vX.Y.Z.tar.gz
optrasight-batchone-vX.Y.Z.tar.gz.asc
SHA256SUMS
SHA256SUMS.asc
```

Verify the checksum manifest:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

Then verify the archive signature:

```bash
gpg --verify optrasight-batchone-vX.Y.Z.tar.gz.asc optrasight-batchone-vX.Y.Z.tar.gz
```

On macOS, use `shasum -a 256 -c SHA256SUMS` if `sha256sum` is not installed.

## Verify A Git Tag

If the release is published as a signed Git tag:

```bash
git fetch --tags
git tag -v vX.Y.Z
```

The tag signer should match the release key fingerprint above.

## Verify The Public Seed Data

BatchOne ships sanitized public seed data under:

```text
data/public/optrasight-threat-intel-public.db
data/public/optrasight-threat-actors-public.db
data/public/portraits/
```

These files are public release assets. They do not contain API keys or private runtime secrets. Local runtime state is restored with:

```bash
npm run db:restore-public
```

This creates local git-ignored runtime files such as `data.db` and `data/portraits/`.

## Security Notes

- Do not trust unsigned archives, altered checksums, or release assets whose fingerprint does not match this file.
- Seed accounts are public first-run credentials. Rotate them and enroll MFA before using OptraSight with real data.
- AI provider keys are never bundled in public seed data. Configure them locally in AI Setup after verification.
- Report suspected signing-key compromise or release tampering using the process in `SECURITY.md`.

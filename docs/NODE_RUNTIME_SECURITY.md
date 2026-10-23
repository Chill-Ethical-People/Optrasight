# Node.js runtime security update — 23 October 2026

## Scope

OptraSight now requires **Node.js >=22.23.4 <23**. This stays on the existing Node
22 LTS line, removes unsupported Node 20 from CI, and aligns development, release
archives and both Docker stages. It does not change pages, features, providers,
database schemas or dependency versions. No private deployment data is included.

The [21 October advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
and [22.23.4 release](https://nodejs.org/en/blog/release/v22.23.4) cover Brotli
(CVE-2026-111497), DNS, TLS and other runtime fixes. These advisories do not prove
that a particular OptraSight installation is exploitable. Node's bundled SQLite
update does not update the separate `better-sqlite3` dependency.

`.npmrc` enforces the package engine range. A dependency-free guard also runs at
installation, development/build/start hooks and at server entry (including the
compiled bundle). Old runtimes intentionally fail with an upgrade message.
There is no runtime-check bypass. No claim is made that this fixed version will
remain current indefinitely: review subsequent Node 22 security releases.

## Safe rollout

1. Record the currently running executable/version and application commit. Check
   service/container configuration, not only your interactive shell's PATH.
2. Back up settings and databases using the platform's existing backup procedure.
   Use an isolated staging checkout and a disposable database for verification.
3. Install the official Node 22.23.4 runtime (or later stable 22.x), verify its
   published checksum/signature, and select it. With nvm: `nvm install && nvm use`.
4. Run `npm ci` under that runtime. Do not copy `node_modules` across operating
   systems, CPU architectures, or Node majors: SQLite and image processing use
   native modules. Do not use `npm update`, `npm audit fix --force`, or delete data
   as part of this runtime-only patch.
5. Run `npm run check:node`, `npm run check`, `npm run build`, and
   `npm run test:runtime`. The last command starts its own short-lived production
   server against disposable data, not your operational database. A nonzero result
   blocks rollout; investigate it, rather than weakening a test or baseline.
6. For Docker, run `docker build --pull -t optrasight:node22-security .` and test
   the resulting image in staging. Do not mount production data during testing.
7. Verify login/MFA/roles/logout, source ingestion and search, assessment and
   client-brief generation with your configured provider, exports, scheduled jobs,
   and `/api/v1/health`. Confirm any notification paths configured on your build.
   A health response alone does not prove these workflows work.
8. Restart all server and worker processes using the patched runtime, verify the
   actual executable/container version, and repeat the functional smoke checks.

CI runs the existing quality checks and production build on the minimum version
and latest Node 22.x. Runtime-policy tests check rejection of vulnerable or
unvalidated versions and synchronization of package, container and release inputs.
Native-module smoke tests exercise in-memory SQLite and image transformation.
Post-build smoke checks cover strict production startup, static UI delivery,
unauthenticated API rejection and invalid-login rejection. CI also builds and
smoke-tests the Linux container with external networking disabled.
Live AI credentials, real mail delivery and a production browser session are not
covered by offline regression tests; operator acceptance remains necessary.

## Recovery

Retain the previous image/application and an isolated backup until acceptance.
On failure, stop the candidate and investigate before exposing it to users.
Prefer rolling back application changes while keeping a patched Node 22 runtime;
do not routinely roll back to vulnerable Node 20/22 binaries. Restoring an older
database over new work can lose data and is not an automatic recovery step.

Updating GitHub does **not** upgrade existing hosts or already running containers.
This change intentionally makes no Windows-device deployment or global runtime
installation changes.

## Verification recorded on 23 October 2026

- Isolated macOS ARM64 runtime: official Node 22.23.4 archive, SHA-256 verified.
- `npm ci` with unchanged locked dependency versions: passed.
- `npm run check`: 28 tests passed; zero-warning ESLint passed; formatting baseline
  passed (109 files versus the existing allowance of 110); TypeScript baseline
  passed (59 diagnostics versus the existing allowance of 85). This is not a
  clean TypeScript compilation; the existing baseline was not raised.
- Production client/server build: passed on macOS and Alpine Linux ARM64.
- Production smoke checks: passed locally and inside the container with external
  networking disabled. The compiled server also rejected a simulated older
  runtime before creating database files.
- Public repository feature implementation and dependency resolutions unchanged.
  These tests do not certify every browser/provider workflow or a Windows device.
- Separate `npm audit` findings remain: 24 total (1 critical, 16 high, 6 moderate,
  1 low), including a critical `proxy-addr` advisory
  ([GHSA-jqcg-44mw-7w3h](https://github.com/advisories/GHSA-jqcg-44mw-7w3h)).
  This runtime-only change does not fix those dependency findings; they require a
  separate reviewed dependency update. Do not interpret the runtime test results
  as an all-clear security assessment.

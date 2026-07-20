## Summary

- 

## Scope

- [ ] BatchOne functionality only
- [ ] No secrets, runtime databases, private client data, generated logs, or local screenshots committed
- [ ] No auth, route, storage, or schema behavior changed unless described below

## Verification

- [ ] `npm run format:baseline`
- [ ] `npm run lint:strict`
- [ ] `npm run typecheck:baseline`
- [ ] `npm test`
- [ ] `npm run build`

## Security Notes

- [ ] Public default credentials remain forced through password change and MFA enrollment
- [ ] New server-side URL fetches use SSRF-safe validation
- [ ] Browser-supplied files use the validated upload service; no route writes request bytes or request-derived paths
- [ ] New client API calls use `apiRequest`, not raw `fetch`
- [ ] New errors avoid returning internal exception details to clients
- [ ] CodeQL and Snyk workflow coverage remains enabled

## Behavior Changes

Describe any user-facing behavior changes, migrations, or compatibility notes:

- 

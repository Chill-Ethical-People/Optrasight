#!/usr/bin/env node

// Restore a local git-ignored BatchOne runtime DB from the public release DBs.
//
// This is intentionally a thin entry point over setup-batchone-demo.cjs so the
// old command remains compatible while fresh-clone users get a clearer name:
//   npm run db:restore-public

require("./setup-batchone-demo.cjs");

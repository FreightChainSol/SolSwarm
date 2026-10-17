#!/usr/bin/env node
/**
 * audit-plans.mjs
 *
 * Detects the target project's technical stacks and risk domains:
 *   1. HTTP / REST / GraphQL APIs (`http`)
 *   2. gRPC & Protobuf Services (`grpc`)
 *   3. WebSockets & Realtime Streams (`websockets`)
 *   4. Databases, Transactions & Row Locking (`databases`)
 *   5. Cryptography, Web3 & On-Chain Custody (`crypto`)
 *   6. Scopes & Roles Validation / IDOR / Plane Separation (`scopes_roles`)
 *   7. Bot / Headless Automation Resistance & Economy Integrity (`bots_economy`)
 *   8. API Abuse & Response DTO / Error Oracle Leakage (`api_dto_abuse`)
 *
 * Generates structured `stack-profile.json` and `review-plans.md` under `/out/harness`
 * and provides surface-tailored check plans for the MCP bridge and agent orchestrator.
 */

import fs from 'node:fs';
import path from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules', 'target', 'dist', 'build', '.git', 'vendor', 'coverage', '.next',
  '__pycache__', 'harness-fixtures', '.cargo', 'reports',
]);
const MAX_FILE = 512 * 1024;
const MAX_LEADS_PER_RULE = 25;

const CODE_EXT = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.go', '.rs',
  '.proto', '.sql', '.prisma', '.graphql', '.gql', '.sol', '.rb', '.php', '.java', '.kt',
]);

export const DOMAIN_SPECS = [
  {
    id: 'http',
    title: 'HTTP / REST / GraphQL APIs',
    surfaces: ['S1', 'S2', 'S4', 'S6'],
    alwaysActive: false,
    summary: 'REST controllers, GraphQL resolvers, route guards, request schema validation, CORS/CSRF, and rate limits.',
    fileMarkers: [
      { re: /@(?:Controller|Get|Post|Put|Delete|Patch|Options|All)\s*\(/g, label: 'NestJS/Decorator HTTP route' },
      { re: /\b(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(\s*['"`/]/g, label: 'Express/Fastify/Hono route' },
      { re: /\b(?:FastAPI|APIRouter|@app\.(?:route|get|post)|http\.HandleFunc|gin\.Engine|axum::Router|actix_web)\b/g, label: 'HTTP framework router' },
      { re: /@(?:Resolver|Query|Mutation)\s*\(|type\s+Query\s*\{/g, label: 'GraphQL resolver/schema' },
    ],
    leads: [
      {
        id: 'http-routes',
        title: 'HTTP Route & Controller Entry Points',
        re: /@(?:Controller|Get|Post|Put|Delete|Patch)\s*\([^)]*\)|\b(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`]/g,
        note: 'Map each route to its auth guard, input schema validator, rate limit, and response DTO.',
      },
      {
        id: 'http-raw-input',
        title: 'Direct Request Input Access (Verify Schema Validation)',
        re: /\breq\.(?:body|query|params|headers)\b|@(?:Body|Query|Param)\s*\(\s*\)/g,
        note: 'Confirm input is validated via strict schema (e.g. @ZodBody/@ZodQuery/@ZodParams) and rejects unknown fields / mass assignment.',
      },
      {
        id: 'http-csrf-origin',
        title: 'Cookie / Origin / CSRF & Host Header Checks',
        re: /\b(?:SameSite|sameSite|csrf|xsrf|headers\.origin|headers\.referer|headers\.host|CORS_ORIGINS)\b/g,
        note: 'Verify cookie-authenticated state changes enforce Origin/CSRF checks and host-bound planes cannot be spoofed.',
      },
    ],
    checks: [
      'Inventory every HTTP controller/route and verify default-deny guard coverage (no accidentally public state-changing routes).',
      'Verify every `@Body`, `@Query`, and `@Param` input uses strict schema validation (rejecting extra keys, prototype pollution, and type coercion tricks).',
      'Check state-changing cookie-authenticated endpoints (`POST`/`PUT`/`PATCH`/`DELETE`) for CSRF protection (`SameSite`, Origin verification, or `__Host-` prefix).',
      'Verify CORS policy: `Access-Control-Allow-Origin: *` must never be combined with `Access-Control-Allow-Credentials: true`, and wildcard origins must be restricted to explicitly public paths (e.g. Solana Actions).',
      'Check rate limiting, request body size caps, and pagination bounds (`limit`/`offset`) on public and high-cost endpoints.',
    ],
  },
  {
    id: 'grpc',
    title: 'gRPC & Protobuf Services',
    surfaces: ['S1', 'S2', 'S4'],
    alwaysActive: false,
    summary: 'Protobuf schemas, unary/streaming RPC handlers, metadata authentication interceptors, message limits, and reflection.',
    fileMarkers: [
      { re: /\bsyntax\s*=\s*["']proto[23]["']|\bservice\s+[A-Za-z0-9_]+\s*\{/g, label: 'Protobuf service schema' },
      { re: /@(?:GrpcMethod|GrpcStreamMethod)\s*\(|\bTransport\.GRPC\b|@grpc\/grpc-js|\btonic::|\bprost::|\bgrpc\.NewServer\b/g, label: 'gRPC server/client runtime' },
    ],
    leads: [
      {
        id: 'grpc-rpc-methods',
        title: 'gRPC Service & Method Definitions',
        re: /\brpc\s+[A-Za-z0-9_]+\s*\(|@(?:GrpcMethod|GrpcStreamMethod)\s*\([^)]*\)/g,
        note: 'Confirm HTTP guards are not assumed to protect gRPC handlers; verify dedicated gRPC auth interceptors/guards.',
      },
      {
        id: 'grpc-metadata-reflection',
        title: 'gRPC Metadata, Reflection & Message Limits',
        re: /\b(?:ServerReflection|tonic_reflection|maxReceiveMessageLength|maxSendMessageLength|Metadata)\b/g,
        note: 'Check if reflection is exposed in production, if metadata tokens are verified, and if message/stream sizes are bounded.',
      },
    ],
    checks: [
      'Verify every `rpc` method and `@GrpcMethod` / `@GrpcStreamMethod` handler enforces authentication and scope/role authorization via gRPC-aware interceptors or guards.',
      'Check for Protobuf proto3 default-value traps (`0`, `""`, `false`, empty repeated fields) that could bypass business logic or permission checks.',
      'Verify client-streaming and bidirectional-streaming RPCs enforce per-stream message rate limits, timeouts, and maximum message byte sizes (`maxReceiveMessageLength`).',
      'Verify gRPC Server Reflection and internal health/debug services are disabled or isolated from untrusted callers.',
    ],
  },
  {
    id: 'websockets',
    title: 'WebSockets & Realtime Streams (WS / Socket.IO / SSE)',
    surfaces: ['S1', 'S2', 'S3', 'S6'],
    alwaysActive: false,
    summary: 'WebSocket gateways, Socket.IO / ws handlers, SSE streams, room/channel join authorization, and frame flood controls.',
    fileMarkers: [
      { re: /@(?:WebSocketGateway|SubscribeMessage|Sse)\s*\(|\bsocket\.io\b|\bWebSocketServer\b|\bnew\s+WebSocket\s*\(|\bgorilla\/websocket\b|\btokio_tungstenite\b/g, label: 'WebSocket / SSE runtime' },
    ],
    leads: [
      {
        id: 'ws-gateways-events',
        title: 'WebSocket Gateways & Message Subscriptions',
        re: /@(?:WebSocketGateway|SubscribeMessage|Sse)\s*\([^)]*\)|\b(?:ws|socket|io)\.on\s*\(\s*['"`](?:connection|message|[a-zA-Z0-9_:-]+)['"`]/g,
        note: 'Verify authentication on both initial handshake AND every subsequent message frame.',
      },
      {
        id: 'ws-rooms-broadcast',
        title: 'WebSocket Room Joins & Stream Broadcasts',
        re: /\b(?:socket|client)\.(?:join|leave|to|emit|send)\s*\(/g,
        note: 'Check room/channel join calls for IDOR (can a user join another user/ride/admin room without authorization?).',
      },
    ],
    checks: [
      'Handshake vs. Per-Frame Auth: Confirm session authentication is validated during upgrade (`handleConnection`) AND session revocation/expiry is checked on ongoing `@SubscribeMessage` frames.',
      'Room & Channel IDOR: Verify that joining a room/topic (`socket.join(roomId)`) or subscribing to a live stream checks that the caller is permitted to view or publish to that specific room.',
      'Cross-Site WebSocket Hijacking (CSWSH): Confirm `Origin` header validation on WebSocket handshakes when cookie authentication is used.',
      'Frame Validation & Backpressure: Verify every incoming WS frame is schema-validated, size-capped, and rate-limited so flooded frames cannot desync state or exhaust memory.',
    ],
  },
  {
    id: 'databases',
    title: 'Databases, Transactions & Concurrency Locking',
    surfaces: ['S1', 'S2', 'S3'],
    alwaysActive: false,
    summary: 'SQL/NoSQL/Redis persistence, row-level locking (`FOR UPDATE`), transaction isolation, TOCTOU races, and query injection.',
    fileMarkers: [
      { re: /@prisma\/client|\b(?:PrismaClient|TypeOrmModule|drizzle-orm|Sequelize|mongoose|ioredis|sqlx::|diesel::|pg|mysql2|sqlite3)\b|datasource\s+db\s*\{/g, label: 'Database / ORM / Redis stack' },
    ],
    leads: [
      {
        id: 'db-locks-transactions',
        title: 'Transactions & Pessimistic Row Locks (`FOR UPDATE`)',
        re: /\$(?:transaction|queryRaw|executeRaw)\b|\bFOR\s+UPDATE\b|\bfindByWalletForUpdate\b|\bisolationLevel\b/gi,
        note: 'Verify all balance/credit/ticket/ride/pledge mutations run in ONE transaction under the correct lock order (e.g. player -> pool -> tickets/pledges).',
      },
      {
        id: 'db-state-mutations',
        title: 'Database Write / Update / Delete Operations',
        re: /\.(?:create|update|updateMany|upsert|delete|deleteMany)\s*\(\s*\{/g,
        note: 'Check if state updates can race (TOCTOU) when called concurrently without a prior `FOR UPDATE` lock, and verify `where` clauses bind the authenticated owner.',
      },
      {
        id: 'db-raw-sql-redis',
        title: 'Raw Queries & Redis Cache / Queue Operations',
        re: /\$(?:queryRawUnsafe|executeRawUnsafe)\b|\.(?:query|raw|eval|evalsha)\s*\(/g,
        note: 'Audit raw SQL/Redis scripts for parameter binding and injection.',
      },
    ],
    checks: [
      'Concurrency & Double-Spend (TOCTOU): Trace every mutation of money, credits, free rides, tickets, pledges, promo redemptions, or state transitions (`running` -> `completed`). Confirm it executes inside a single transaction under a pessimistic row lock (`SELECT ... FOR UPDATE` / `findByWalletForUpdate`).',
      'Lock Ordering & Deadlocks: When locking multiple rows (e.g. player, pool, ticket/pledge), confirm a strict canonical lock acquisition order across all handlers.',
      'Check-Then-Act Gaps: Look for `findUnique`/`findFirst` followed by `.create`/`.update` outside a locked transaction where parallel requests can pass the check twice.',
      'Scope-Bound Queries: Confirm every `UPDATE`/`DELETE`/`SELECT` on user-owned records includes the authenticated user/wallet scope in the `WHERE` clause.',
      'Redis / Cache Consistency: Check whether cached stats, rate limits, or job queues (`replay:worker`) can be poisoned, replayed, or desynchronized from PostgreSQL on transaction rollback.',
    ],
  },
  {
    id: 'crypto',
    title: 'Cryptography, Web3 Signatures & On-Chain Custody',
    surfaces: ['S1', 'S3', 'S4', 'S6'],
    alwaysActive: false,
    summary: 'Solana/Anchor programs, Ed25519/SIWS authentication, Merkle roots & proofs, deterministic PRNG seeds, and key custody.',
    fileMarkers: [
      { re: /@solana\/web3\.js|\b(?:anchor_lang|solana_program|tweetnacl|ed25519|ethers|viem|mulberry32|createHash|subtle\.digest)\b/g, label: 'Crypto / Web3 / PRNG stack' },
    ],
    leads: [
      {
        id: 'crypto-sig-challenge',
        title: 'Signature Verification, SIWS Challenges & Nonces',
        re: /\b(?:sign\.detached\.verify|verifyMessage|solana:signIn|signMessage|challenge|nonce)\b/g,
        note: 'Verify the signed payload is compared byte-for-byte against the server-issued challenge (domain, wallet, nonce, expiry) and consumed once.',
      },
      {
        id: 'crypto-merkle-hash',
        title: 'Merkle Proofs, Telemetry Roots & Hash Commitments',
        re: /\b(?:merkle|winners_root|telemetry_root|createHash\s*\(\s*['"`]sha256['"`]|keccak256)\b/gi,
        note: 'Check leaf encoding for domain separation and unambiguous field boundaries so concatenation collisions or forged leaves are impossible.',
      },
      {
        id: 'crypto-prng-random',
        title: 'Randomness & Seed Generation (`Math.random` vs Seeded/CSPRNG)',
        re: /\b(?:Math\.random\s*\(|mulberry32|randomBytes|randomUUID|getRandomValues)\b/g,
        note: 'Confirm `Math.random()` is never used for gameplay, challenges, or tokens, and deterministic seeds are server-authoritative.',
      },
    ],
    checks: [
      'SIWS / Wallet Signature Binding: Confirm sign-in and wallet-signed admin/action payloads verify the exact server-issued challenge byte-for-byte, bind the wallet + host/domain + expiration + single-use nonce, and reject replay.',
      'On-Chain Escrow & Program Invariants: Verify `Signer` == stored authority (`has_one`), account `owner` checks, PDA seed/bump canonicalization, fixed CPI program IDs, `reload()` after CPIs, and closed-account revival prevention.',
      'Merkle Root & Attestation Integrity: Verify winners roots and ride attestations commit all critical fields (pool, wallet, amount/rank, verdict) with collision-resistant leaf formatting and respect review/veto lock windows.',
      'PRNG & Seed Authority: Verify gameplay and reward randomness uses server-stamped seeds (`mulberry32`) or CSPRNG (`crypto.randomBytes`), never `Math.random()`.',
    ],
  },
  {
    id: 'scopes_roles',
    title: 'Scopes, Roles & Access Control Misvalidation',
    surfaces: ['S1', 'S3', 'S4'],
    alwaysActive: true,
    summary: 'Horizontal privilege escalation (IDOR), vertical role/admin bypass, host/plane isolation, and token/ticket scope confusion.',
    fileMarkers: [],
    leads: [
      {
        id: 'scope-guards-planes',
        title: 'Authentication Guards, Admin Checks & Host Plane Restrictions',
        re: /@(?:UseGuards|Public|Admin|Roles)\b|\bcanActivate\b|\bfc_admin\b|\b__Host-fc_session\b|\bheaders\.host\b/g,
        note: 'Check every controller/handler to ensure admin routes require both `fc_admin` session AND `admin.<domain>` host, plus wallet-signed audit where required.',
      },
      {
        id: 'scope-resource-lookup',
        title: 'Resource Lookups by ID / Wallet (IDOR & Ownership Check)',
        re: /@(?:Param|ZodParams)\b|\bfind(?:Unique|First|ById)\s*\(\s*\{[^}]{0,120}\bid\b/g,
        note: 'Trace whether the fetched resource (ride, ticket, pledge, replay, profile) is verified to belong to the caller session wallet before mutation or private read.',
      },
    ],
    checks: [
      'Horizontal Scope Validation (IDOR): For every route taking a `rideId`, `poolId`, `ticketId`, `pledgeId`, or `wallet`, verify that the handler checks ownership against the authenticated session wallet — never trust a wallet/userId passed in the request body or query when acting on behalf of a session.',
      'Vertical Role & Plane Separation: Verify admin routes cannot be called with a regular player session (`__Host-fc_session`) or from a non-admin host header, and verify all new routes are guarded by default.',
      'Cross-Scope Token / Ticket Confusion: Verify that a demo/guest session, free-ride entitlement, or ticket purchased for Pool A cannot be pledged, settled, or counted toward Pool B or real-wallet leaderboards/stats.',
      'Revoked / Stale State Scope: Verify that once a ride is ended, expired (`HB_TIMEOUT_MS`), or its verdict is revoked/flagged/held, its scope no longer permits further heartbeats, telemetry uploads, or prize payouts.',
    ],
  },
  {
    id: 'bots_economy',
    title: 'Bot / Headless Automation Resistance & Economy Integrity',
    surfaces: ['S1', 'S2', 'S3', 'S6'],
    alwaysActive: true,
    summary: 'Protection of paid prize pools, game physics/traffic verification, telemetry proofs, replay plagiarism, seed lookahead, and sybil farming.',
    fileMarkers: [
      { re: /\b(?:ReplayEngine|telemetry|verdict|heartbeat|completeDist|freeRides|promo|pledge|payout|winners_root)\b/g, label: 'Game / Prize Economy / Anti-Cheat surface' },
    ],
    leads: [
      {
        id: 'bot-telemetry-replay',
        title: 'Telemetry Verification, Replay Engine & Verdict Rules',
        re: /\b(?:ReplayEngine|verifyRide|verdict|telemetry_root|traffic|completeDist|HB_TIMEOUT_MS)\b/g,
        note: 'Check if a headless bot can forge telemetry, strip traffic collisions, coast/speed-hack, send empty batches, or replay another rider\'s recording.',
      },
      {
        id: 'bot-economy-promos',
        title: 'Prize Pools, Free Rides, Promo Codes & Sybil Surfaces',
        re: /\b(?:redeemPromo|freeRides|createRide|pledge|claim|payout|sponsor|donate)\b/gi,
        note: 'Check if bots can farm promo codes/free rides, cherry-pick seeds before paying, enter after pool sale cutoff, or stall pool settlement.',
      },
    ],
    checks: [
      'Headless Bot Simulation Bypass: Assume an attacker bypasses the browser client completely and sends synthesized HTTP heartbeats and telemetry batches. Verify the server independently reconstructs the road, physics, and traffic (`ReplayEngine`) and rejects missing frame-level traffic proofs, ignored collisions, speed-governor violations, or impossible wall-clock/game-clock ratios.',
      'Cross-Rider Replay Plagiarism: Check whether a valid winning recording copied from another player in the same pool (or a practice/free ride) can be submitted by a bot. Confirm recordings are checked for cross-rider duplication and bound to the ride context.',
      'Seed & Route Lookahead Abuse: Check when the ride `seed`, `route`, and `startHour` are revealed vs. when the paid ticket/pledge is committed. Can a bot inspect the seed first, pre-simulate difficulty, and abort/avoid burning its ticket on hard seeds?',
      'Pool Timing, Cutoff & Settlement Griefing: Verify a bot cannot buy a ticket or start a pledged ride after the pool sale cutoff, cannot count a ride finished after the play deadline, and cannot stall pool payout by starting a pledged ride and abandoning it.',
      'Sybil Farming (Promo Codes, Free Rides, Badges): Check whether automated wallets can brute-force or double-redeem promo codes, farm transferable value from free rides, or trigger cNFT badge mints on rejected/flagged rides.',
    ],
  },
  {
    id: 'api_dto_abuse',
    title: 'API Abuse, Response DTO Leakage & Enumeration Oracles',
    surfaces: ['S1', 'S2', 'S4', 'S6'],
    alwaysActive: true,
    summary: 'Response DTO inspection, user/state enumeration oracles (e.g. "already registered"), over-broad entity serialization, and endpoint abuse.',
    fileMarkers: [],
    leads: [
      {
        id: 'dto-enumeration-messages',
        title: 'State & User Enumeration Oracles in Error / Response Messages',
        re: /['"`][^'"`\n]*\b(?:already\s+(?:registered|exists|used|claimed|redeemed|pledged)|not\s+found|invalid\s+(?:password|code|promo|signature|challenge)|no\s+such\s+user)\b[^'"`\n]*['"`]/gi,
        note: 'Double-check every distinct message/status code: if a public or unthrottled API reveals whether a user, wallet, promo code, or resource exists, check if bots can abuse it as an enumeration oracle.',
      },
      {
        id: 'dto-serializers-returns',
        title: 'Controller Response DTOs & Serialization Boundaries',
        re: /\b(?:Dto|Response|toJson|toResponse|serialize)\b|@(?:ZodSerializerDto|SerializeOptions)\b/g,
        note: 'Verify responses use explicit allowlist DTOs and never serialize raw DB rows, internal secrets, unredacted seeds, or other users\' private fields.',
      },
      {
        id: 'api-abuse-throttling',
        title: 'Rate Limits, Batch Caps & Public Action Endpoints',
        re: /@(?:Throttle|SkipThrottle)\b|\b(?:rateLimit|maxItems|batch|actions\.json|\/api\/actions)\b/g,
        note: 'Check public/unauthenticated endpoints and batch uploaders for missing rate limits, unbounded array sizes, or amplification.',
      },
    ],
    checks: [
      'Response Message & Status Oracles (e.g. "User Already Registered"): Inspect login, registration, challenge, promo redemption, and lookup endpoints. When an endpoint returns a distinct message or status code (such as `"user already registered"`, `"promo code already used"`, vs `"invalid code"`), double-check whether an unauthenticated caller or bot can abuse it to enumerate accounts, valid promo codes, or private player state.',
      'Response DTO Over-Exposure: Trace the exact object returned by every controller/handler. Confirm handlers map domain entities to strict response DTOs (allowlist) rather than returning raw Prisma/DB models containing internal IDs, secret seeds, admin notes, session hashes, or other players\' data.',
      'Public Endpoint & Blink Abuse: On public endpoints (e.g. `/api/actions/*`, `/api/stats`, `/api/live`, `/api/replays`, sign-in challenge), check if a bot can flood requests to exhaust DB connections, pollute in-memory challenge stores, or scrape sensitive ride telemetry before a pool closes.',
      'Idempotency & Replay Abuse: Check whether retrying or re-sending a valid payment signature, batch upload, or donation request can credit a player twice or corrupt running totals (`StatsService`).',
    ],
  },
];

function walkFiles(root, onFile) {
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (ent.isSymbolicLink()) continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
      } else if (ent.isFile()) {
        onFile(full);
      }
    }
  }
}

function relPath(root, file) {
  return path.relative(root, file).split(path.sep).join('/');
}

function findLineMatches(text, regex, maxHits) {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const re = new RegExp(regex.source, flags);
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const lineNum = text.slice(0, m.index).split('\n').length;
    const lineText = (text.split('\n')[lineNum - 1] || '').trim().slice(0, 140);
    out.push({ line: lineNum, snippet: lineText });
    if (out.length >= maxHits) break;
  }
  return out;
}

export function analyzeStackAndPlans(targetRoot) {
  const root = path.resolve(targetRoot);
  const state = new Map();
  for (const spec of DOMAIN_SPECS) {
    state.set(spec.id, {
      id: spec.id,
      title: spec.title,
      surfaces: spec.surfaces,
      alwaysActive: spec.alwaysActive,
      summary: spec.summary,
      detected: spec.alwaysActive,
      markerHits: [],
      leads: spec.leads.map((l) => ({ id: l.id, title: l.title, note: l.note, hits: [] })),
      checks: REVIEW_CHECKS[spec.id] || ['Inspect cited source and existing tests; record coverage limits.'],
    });
  }

  let scannedFiles = 0;
  walkFiles(root, (file) => {
    const ext = path.extname(file).toLowerCase();
    const base = path.basename(file);
    if (!CODE_EXT.has(ext) && base !== 'Anchor.toml' && base !== 'Cargo.toml' && base !== 'package.json') return;
    let st;
    try { st = fs.lstatSync(file); } catch { return; }
    if (!st.isFile() || st.size === 0 || st.size > MAX_FILE) return;
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { return; }
    if (text.includes('\0')) return;

    scannedFiles++;
    const rel = relPath(root, file);

    for (const spec of DOMAIN_SPECS) {
      const dom = state.get(spec.id);
      for (const marker of spec.fileMarkers) {
        const matches = findLineMatches(text, marker.re, 5);
        if (matches.length) {
          dom.detected = true;
          for (const hit of matches) {
            if (dom.markerHits.length < 15) {
              dom.markerHits.push(`${rel}:${hit.line} (${marker.label})`);
            }
          }
        }
      }
      for (let i = 0; i < spec.leads.length; i++) {
        const rule = spec.leads[i];
        const bucket = dom.leads[i].hits;
        if (bucket.length >= MAX_LEADS_PER_RULE) continue;
        const matches = findLineMatches(text, rule.re, MAX_LEADS_PER_RULE - bucket.length);
        if (matches.length) {
          dom.detected = true;
          for (const hit of matches) {
            bucket.push({ citation: `${rel}:${hit.line}`, snippet: hit.snippet });
          }
        }
      }
    }
  });

  const domains = [...state.values()].map((d) => ({
    ...d,
    totalLeads: d.leads.reduce((acc, l) => acc + l.hits.length, 0),
  }));

  return {
    scannedFiles,
    detectedStacks: domains.filter((d) => d.detected).map((d) => d.id),
    domains,
  };
}

const REVIEW_CHECKS = {
  http: ['Trace authentication, authorization, request validation, response fields and error handling in source.', 'Inspect CORS, CSRF, rate-limit and request-size configuration; cite missing controls and existing tests.'],
  grpc: ['Inspect protobuf schemas, authentication metadata, message bounds, deadlines and stream cancellation in source.', 'Check existing tests for authorization and resource-limit handling; do not send traffic to services.'],
  websockets: ['Trace upgrade authentication, Origin checks, room membership and per-message authorization in source.', 'Inspect frame bounds, cleanup, rate limits and existing coverage.'],
  databases: ['Trace queries, transactions, lock ordering, uniqueness constraints and rollback behavior.', 'Inspect parameter binding and existing concurrency tests; disclose untested schedules.'],
  crypto: ['Trace signer/owner checks, authority binding, PDA seeds, nonce expiry, custody and payout invariants.', 'Inspect dependency pins and existing signature/account-validation tests without constructing transactions or PoCs.'],
  scopes_roles: ['Map resource ownership and role checks from authenticated identity to each handler.', 'Compare admin, player and public entry points and cite inconsistent boundaries in source.'],
  bots_economy: ['Inspect server authority, replay validation, uniqueness, deadlines and economic state transitions.', 'Assess abuse resistance from source and existing tests; do not build automation clients or forged recordings.'],
  api_dto_abuse: ['Compare response DTOs and errors with authorization and data-minimization requirements.', 'Trace field selection and enumeration differences in source; do not probe accounts or endpoints.'],
};

export function renderReviewPlansMarkdown(profile, surfaceFilter = '') {
  const filter = String(surfaceFilter || '').toUpperCase();
  const lines = [
    '# Stack Inventory & Source Security Review Plans',
    '',
    `Files scanned: ${profile.scannedFiles} | Active domains: ${profile.detectedStacks.join(', ') || 'none'}`,
    '',
    '## Stack & Risk Domain Matrix',
    '',
    '| Domain ID | Subsystem / Focus | Status | Leads | Primary Surfaces |',
    '|---|---|---|---:|---|',
  ];

  for (const d of profile.domains) {
    lines.push(`| \`${d.id}\` | ${d.title} | **${d.detected ? 'DETECTED' : 'absent'}** | ${d.totalLeads} | ${d.surfaces.join(', ')} |`);
  }
  lines.push('');

  for (const d of profile.domains) {
    if (filter && /^S[1-6]$/.test(filter) && !d.surfaces.includes(filter)) continue;
    lines.push(`## [${d.id.toUpperCase()}] ${d.title} (${d.detected ? 'DETECTED' : 'absent'})`);
    lines.push(`- **Surfaces**: ${d.surfaces.join(', ')}`);
    lines.push(`- **Scope**: ${d.summary}`);
    if (!d.detected) {
      lines.push('- **Status**: No markers or entry points detected in the repository. Confirm absence quickly and record `n/a`.', '');
      continue;
    }
    if (d.markerHits.length) {
      lines.push(`- **Detected Stack Markers**: ${d.markerHits.slice(0, 6).map((m) => `\`${m}\``).join(', ')}`);
    }
    lines.push('', '### Source Review Checks');
    for (const [idx, chk] of (REVIEW_CHECKS[d.id] || ['Inspect the cited source and existing tests; record evidence and coverage limits.']).entries()) {
      lines.push(`${idx + 1}. ${chk}`);
    }
    lines.push('', '### Codebase Entry Points & Leads');
    for (const lead of d.leads) {
      lines.push(`#### ${lead.id}: ${lead.title}`);
      lines.push(`_${lead.note}_`);
      if (!lead.hits.length) {
        lines.push('- no direct regex hit (perform manual source trace)');
      } else {
        for (const h of lead.hits.slice(0, 15)) {
          lines.push(`- \`${h.citation}\` — \`${h.snippet.replace(/`/g, "'")}\``);
        }
      }
      lines.push('');
    }
  }

  return lines.join('\n') + '\n';
}

export function renderSurfaceSkillGuidance(surfaceCode) {
  const code = String(surfaceCode || 'S1').toUpperCase();
  const common = [
    '### Mandatory Cross-Cutting Skill Checks (Apply to Every Surface)',
    '1. **Scopes & Roles Misvalidation (IDOR / RBAC / Plane Separation)**:',
    '   - Verify every handler that reads or mutates a resource by ID/wallet checks ownership against the authenticated session wallet.',
    '   - Verify vertical privilege separation (e.g. admin session + admin host header + wallet signature; guest/demo vs real wallet; free ride vs paid pool).',
    '2. **Bot / Headless Automation & Economy Integrity**:',
    '   - Ask: "Can a headless bot, script, or sybil farm break the product idea or drain the prize/reward economy?"',
    '   - Verify server-side authoritative simulation/replay checks, frame-level proofs, seed lookahead protection, cross-player replay detection, and pool deadline/revocation gates.',
    '3. **API Abuse & Response DTO / Enumeration Oracles**:',
    '   - Inspect every controller response DTO and error message (e.g. login/signup/promo returning `"user already registered"`, `"already exists"`, or distinct HTTP status codes).',
    '   - Double-check if true in source: if an API leaks account/resource existence or internal entity fields (raw ORM models, seeds, flags), report how bots or attackers can abuse it.',
  ];

  const perSurface = {
    S1: [
      '### S1 Skill Focus — Identity, Scopes, Roles & Auth Planes (`http`, `grpc`, `websockets`, `crypto`, `scopes_roles`, `api_dto_abuse`)',
      '- Audit HTTP/gRPC/WebSocket authentication guards, session cookies (`__Host-`, `httpOnly`, `SameSite`, `Secure`), and CSRF/Origin checks.',
      '- Audit SIWS / wallet signature verification: challenge byte-for-byte equality, domain binding, single-use nonce, expiry.',
      '- Audit horizontal IDOR on every `:id` / `:wallet` endpoint and vertical role bypass between player, spectator, crank, and admin planes.',
      '- Audit auth/login/registration/challenge response DTOs for user/wallet enumeration oracles.',
    ],
    S2: [
      '### S2 Skill Focus — Input Handling, Protocol Parsing & Abuse (`http`, `grpc`, `websockets`, `databases`, `api_dto_abuse`)',
      '- Audit HTTP `@ZodBody/@ZodQuery/@ZodParams`, gRPC protobuf zero-value traps & message limits, and WebSocket frame validation.',
      '- Audit SQL/NoSQL/Redis queries, command execution, SSRF, and path traversal sinks.',
      '- Audit public/batch endpoints (e.g. telemetry upload, blinks/actions) for payload size bounds, rate limits, and malformed batch handling.',
    ],
    S3: [
      '### S3 Skill Focus — Business Logic, Bot/Economy Integrity, DB Locks & Crypto Custody (`bots_economy`, `databases`, `crypto`, `scopes_roles`)',
      '- Audit all money, credit, ticket, pledge, promo, and ride state transitions: confirm single-transaction execution under `FOR UPDATE` row locks in canonical lock order.',
      '- Audit bot & headless cheat vectors: forged telemetry, stripped traffic collisions, speed/clock manipulation, copied recordings across riders, seed lookahead before ticket commitment, and abandoned-pledge payout stalls.',
      '- Audit Solana/Anchor escrow invariants: `Signer` == stored authority, account owner checks, canonical PDA bumps, fixed CPI targets, `reload()` after CPI, and Merkle proof/root attestation rules.',
    ],
    S4: [
      '### S4 Skill Focus — Secrets, Config, Infrastructure & Response DTO Exposure (`api_dto_abuse`, `http`, `grpc`)',
      '- Audit response DTOs and error filters across all APIs for leaked internal fields, stack traces, secrets, or state enumeration messages.',
      '- Audit `.env` handling, key custody (crank, payout, mint keys), Dockerfiles, nginx/proxy headers, TLS settings, and gRPC reflection exposure.',
    ],
    S5: [
      '### S5 Skill Focus — Dependencies, Lockfiles, CI & Verifiable Builds (`crypto`, `http`)',
      '- Audit Rust (`Cargo.lock`) and JS (`package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`) advisories and reachability.',
      '- Audit GitHub Actions (`pull_request_target`, unpinned actions), install scripts, and Solana verifiable build pinning (`cargo-build-sbf`).',
    ],
    S6: [
      '### S6 Skill Focus — Client, Web Surface, WebSockets, Blinks & Economy Client Boundary (`http`, `websockets`, `crypto`, `bots_economy`, `api_dto_abuse`)',
      '- Audit DOM XSS sinks, `postMessage` origin checks, CSP/SRI, CORS (`*` vs credentials), and WebSocket CSWSH.',
      '- Audit Solana Actions / Blinks (`/actions.json`, `/api/actions/*`) and wallet transaction signing flows.',
      '- Audit what API response DTOs expose to the browser (e.g. hidden seeds, other riders\' live data) and verify client-side checks are never relied upon as security.',
    ],
  };

  return [...(perSurface[code] || perSurface.S1), '', ...common].join('\n');
}

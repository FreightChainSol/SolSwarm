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
import { detectEcosystems, isProductionPath } from './stack-detect.mjs';

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
      { re: /@\w+\.(?:get|post|put|delete|patch|route|api_route)\s*\(\s*['"]|\burlpatterns\b|\bAPIView\b|\bViewSet\b|\bBlueprint\s*\(/g, label: 'Python HTTP route (FastAPI/Flask/Django/DRF)' },
    ],
    leads: [
      {
        id: 'http-routes',
        title: 'HTTP Route & Controller Entry Points',
        re: /@(?:Controller|Get|Post|Put|Delete|Patch)\s*\([^)]*\)|\b(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`]+['"`]|@\w+\.(?:get|post|put|delete|patch|route|api_route)\s*\(\s*['"][^'"]+['"]|\burlpatterns\b|\bclass\s+\w+\((?:\w+\.)?(?:APIView|ViewSet|ModelViewSet|GenericAPIView)\)/g,
        note: 'Map each route to its auth guard, input schema validator, rate limit, and response DTO.',
      },
      {
        id: 'http-raw-input',
        title: 'Direct Request Input Access (Verify Schema Validation)',
        re: /\breq\.(?:body|query|params|headers)\b|@(?:Body|Query|Param)\s*\(\s*\)|\brequest\.(?:json|form|args|GET|POST|data|query_params|body)\b|await\s+request\.(?:json|body|form)\s*\(|\b(?:Body|Query|Form|Header|Cookie)\s*\(|\*\*\w*(?:payload|body|data)\w*\.(?:dict|model_dump)\s*\(|\*\*request\./g,
        note: 'Confirm input is validated via strict schema (e.g. @ZodBody/@ZodQuery/@ZodParams) and rejects unknown fields / mass assignment.',
      },
      {
        id: 'http-csrf-origin',
        title: 'Cookie / Origin / CSRF & Host Header Checks',
        re: /\b(?:SameSite|sameSite|samesite|csrf|xsrf|csrf_exempt|CSRFMiddleware|CORSMiddleware|allow_origins|allow_credentials|CORS_ALLOWED_ORIGINS|SESSION_COOKIE_\w+|TrustedHostMiddleware|headers\.origin|headers\.referer|headers\.host|CORS_ORIGINS)\b/g,
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
      { re: /@(?:GrpcMethod|GrpcStreamMethod)\s*\(|\bTransport\.GRPC\b|@grpc\/grpc-js|\btonic::|\bprost::|\bgrpc\.NewServer\b|\bgrpc\.(?:aio\.)?server\s*\(|_pb2_grpc\b/g, label: 'gRPC server/client runtime' },
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
        re: /\b(?:ServerReflection|tonic_reflection|reflection\.enable_server_reflection|maxReceiveMessageLength|maxSendMessageLength|grpc\.max_receive_message_length|ServerInterceptor|invocation_metadata)\b|\bgrpc\.Metadata\b|\bnew\s+Metadata\s*\(/g,
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
      { re: /@(?:WebSocketGateway|SubscribeMessage|Sse)\s*\(|\bsocket\.io\b|\bWebSocketServer\b|\bnew\s+WebSocket\s*\(|\bgorilla\/websocket\b|\btokio_tungstenite\b|@\w+\.websocket\s*\(|\bWebSocketEndpoint\b|\bwebsockets\.(?:serve|connect|asyncio)|\bAsyncWebsocketConsumer\b|\bEventSourceResponse\b/g, label: 'WebSocket / SSE runtime' },
    ],
    leads: [
      {
        id: 'ws-gateways-events',
        title: 'WebSocket Gateways & Message Subscriptions',
        re: /@(?:WebSocketGateway|SubscribeMessage|Sse)\s*\([^)]*\)|@\w+\.websocket\s*\([^)]*\)|\basync\s+def\s+(?:websocket_\w+|\w*ws_\w*)\s*\(\s*\w*\s*:?\s*WebSocket\b|\bwebsocket\.(?:accept|receive_\w+|send_\w+)\s*\(|\b(?:ws|socket|io)\.on\s*\(\s*['"`](?:connection|message|[a-zA-Z0-9_:-]+)['"`]/g,
        note: 'Verify authentication on both initial handshake AND every subsequent message frame.',
      },
      {
        id: 'ws-rooms-broadcast',
        title: 'WebSocket Room Joins & Stream Broadcasts',
        re: /\b(?:socket|client)\.(?:join|leave|to|emit|send)\s*\(|\bgroup_(?:add|send)\s*\(|\b(?:manager|hub|connections)\.(?:broadcast|connect|subscribe|join)\s*\(/g,
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
      { re: /@prisma\/client|\b(?:PrismaClient|TypeOrmModule|drizzle-orm|Sequelize|mongoose|ioredis|sqlx::|diesel::|pg|mysql2|sqlite3)\b|datasource\s+db\s*\{|\b(?:sqlalchemy|psycopg2?|asyncpg|aiosqlite|peewee|tortoise|aioredis|redis\.asyncio|django\.db)\b/g, label: 'Database / ORM / Redis stack' },
    ],
    leads: [
      {
        id: 'db-locks-transactions',
        title: 'Transactions & Pessimistic Row Locks (`FOR UPDATE`)',
        re: /\$(?:transaction|queryRaw|executeRaw)\b|\bFOR\s+UPDATE\b|\bfindByWalletForUpdate\b|\bisolationLevel\b|\bwith_for_update\b|\bselect_for_update\b|\btransaction\.atomic\b|\bisolation_level\b|\bsession\.begin\b/gi,
        note: 'Verify all balance/credit/ticket/ride/pledge mutations run in ONE transaction under the correct lock order (e.g. player -> pool -> tickets/pledges).',
      },
      {
        id: 'db-state-mutations',
        title: 'Database Write / Update / Delete Operations',
        re: /\.(?:create|update|updateMany|upsert|delete|deleteMany)\s*\(\s*\{|\bsession\.(?:add|add_all|delete|merge|flush|commit)\s*\(|\.objects\.(?:create|bulk_create|update_or_create|get_or_create)\s*\(|\.(?:save|bulk_update)\s*\(/g,
        note: 'Check if state updates can race (TOCTOU) when called concurrently without a prior `FOR UPDATE` lock, and verify `where` clauses bind the authenticated owner.',
      },
      {
        id: 'db-raw-sql-redis',
        title: 'Raw Queries & Redis Cache / Queue Operations',
        re: /\$(?:queryRawUnsafe|executeRawUnsafe)\b|\.(?:query|raw|eval|evalsha|extra)\s*\(|\b(?:execute|executemany)\s*\(\s*(?:f['"]|['"][^'"\n]*(?:%s|%\(|\{))|\btext\s*\(\s*f?['"]|\bRawSQL\s*\(/g,
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
      { re: /@solana\/web3\.js|\b(?:anchor_lang|solana_program|tweetnacl|ed25519|ethers|viem|mulberry32|createHash|subtle\.digest|solders\b|\bnacl\b|\bPyNaCl\b|cryptography\.hazmat|\bjose\.jwt\b|\bhmac\.compare_digest)\b/g, label: 'Crypto / Web3 / PRNG stack' },
    ],
    leads: [
      {
        id: 'crypto-sig-challenge',
        title: 'Signature Verification, SIWS Challenges & Nonces',
        re: /\b(?:sign\.detached\.verify|verifyMessage|solana:signIn|signMessage|challenge|nonce|verify_signature|VerifyKey|BadSignatureError|Signature\.from_bytes|compare_digest)\b/g,
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
        re: /\b(?:Math\.random\s*\(|mulberry32|randomBytes|randomUUID|getRandomValues|random\.(?:random|randint|choice|choices|shuffle|seed|getrandbits)\s*\(|secrets\.token_\w+|os\.urandom|uuid\.uuid[14])\b/g,
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
        re: /@(?:UseGuards|Public|Admin|Roles)\b|\bcanActivate\b|\bfc_admin\b|\b__Host-fc_session\b|\bheaders\.host\b|\bDepends\s*\(\s*\w*(?:auth|user|admin|current|permission|role|session|wallet)\w*|\bSecurity\s*\(|\bpermission_classes\b|@(?:login_required|permission_required|user_passes_test)\b|\bis_(?:staff|superuser|admin)\b|\brequire_(?:admin|role|auth)\w*/g,
        note: 'Check every controller/handler to ensure admin routes require both `fc_admin` session AND `admin.<domain>` host, plus wallet-signed audit where required.',
      },
      {
        id: 'scope-resource-lookup',
        title: 'Resource Lookups by ID / Wallet (IDOR & Ownership Check)',
        re: /@(?:Param|ZodParams)\b|\bfind(?:Unique|First|ById)\s*\(\s*\{[^}]{0,120}\bid\b|\bget_object_or_404\s*\(|\.(?:get|filter|filter_by)\s*\([^)\n]{0,120}\b\w*_?id\s*=|\bsession\.get\s*\(\s*\w+\s*,/g,
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
        id: 'bot-background-jobs',
        title: 'Background Jobs, Schedulers & Async Workers',
        re: /@(?:shared_task|(?:celery|app|\w+_app)\.task)\b|\.(?:delay|apply_async)\s*\(|\bAsyncIOScheduler\b|\bBackgroundTasks\b|\basyncio\.create_task\s*\(|\bcrontab\s*\(/g,
        note: 'Check job idempotency and double-execution (retries, overlapping schedules, multiple workers) for money, payout and state transitions; confirm job inputs are server-derived.',
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
        re: /\b(?:Dto|Response|toJson|toResponse|serialize)\b|@(?:ZodSerializerDto|SerializeOptions)\b|\bresponse_model\b|\.model_dump\s*\(|\.dict\s*\(\s*\)|\bfrom_orm\b|\bserializers\.\w+|\bJsonResponse\s*\(|\bjsonify\s*\(/g,
        note: 'Verify responses use explicit allowlist DTOs and never serialize raw DB rows, internal secrets, unredacted seeds, or other users\' private fields.',
      },
      {
        id: 'api-abuse-throttling',
        title: 'Rate Limits, Batch Caps & Public Action Endpoints',
        re: /@(?:Throttle|SkipThrottle)\b|\b(?:rateLimit|maxItems|batch|actions\.json|\/api\/actions)\b|\b(?:slowapi|Limiter|limiter\.limit|throttle_classes|ratelimit|max_length|max_items|le=\d+)\b/g,
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
      testOnlyHits: 0,
      leads: spec.leads.map((l) => ({ id: l.id, title: l.title, note: l.note, hits: [] })),
      checks: REVIEW_CHECKS[spec.id] || ['Inspect cited source and existing tests; record coverage limits.'],
    });
  }

  let scannedFiles = 0;
  // Application code is read first so lead caps are not consumed by tests, docs and helper scripts,
  // and a domain counts as detected only when production code (not a test or doc) carries its markers.
  const candidates = [];
  walkFiles(root, (file) => {
    const ext = path.extname(file).toLowerCase();
    const base = path.basename(file);
    if (!CODE_EXT.has(ext) && base !== 'Anchor.toml' && base !== 'Cargo.toml' && base !== 'package.json') return;
    candidates.push({ file, production: isProductionPath(relPath(root, file)) });
  });
  candidates.sort((a, b) => Number(b.production) - Number(a.production));
  for (const { file, production } of candidates) {
    let st;
    try { st = fs.lstatSync(file); } catch { continue; }
    if (!st.isFile() || st.size === 0 || st.size > MAX_FILE) continue;
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    if (text.includes('\0')) continue;

    scannedFiles++;
    const rel = relPath(root, file);

    for (const spec of DOMAIN_SPECS) {
      const dom = state.get(spec.id);
      for (const marker of spec.fileMarkers) {
        const matches = findLineMatches(text, marker.re, 5);
        if (matches.length) {
          if (production) dom.detected = true; else dom.testOnlyHits++;
          for (const hit of matches) {
            if (dom.markerHits.length < 15) {
              dom.markerHits.push(`${rel}:${hit.line} (${marker.label}${production ? '' : ', non-production'})`);
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
          if (production) dom.detected = true; else dom.testOnlyHits++;
          for (const hit of matches) {
            bucket.push({ citation: `${rel}:${hit.line}`, snippet: hit.snippet, production });
          }
        }
      }
    }
  }

  const domains = [...state.values()].map((d) => ({
    ...d,
    totalLeads: d.leads.reduce((acc, l) => acc + l.hits.length, 0),
  }));

  return {
    scannedFiles,
    ecosystems: detectEcosystems(root),
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

// Python-specific source checks, added to a domain's plan only when Python is a detected ecosystem.
export const PYTHON_CHECKS = {
  http: [
    'FastAPI/Starlette: every router must carry its auth `Depends(...)` (router-level or per-route); list routes with no dependency and confirm each is intentionally public. Check `include_router(..., dependencies=[...])` coverage and middleware ordering.',
    'Django/DRF: compare `permission_classes`/`DEFAULT_PERMISSION_CLASSES`, `csrf_exempt`, `DEBUG`, `ALLOWED_HOSTS`, `SECURE_*`/`SESSION_COOKIE_*` settings; Flask: `SECRET_KEY` source, session cookie flags, `Blueprint` before_request guards.',
    'Pydantic: request models should forbid unknown fields (`extra="forbid"`) and bound `max_length`/`ge`/`le`; flag `**payload.dict()`/`model_dump()` spread into ORM constructors or updates (mass assignment of role, owner, balance fields).',
    'CORS: `CORSMiddleware` with `allow_origins=["*"]` or reflected origin together with `allow_credentials=True`; cookie-authenticated state changes need Origin/CSRF checks (Starlette has no default CSRF).',
  ],
  grpc: ['grpcio: server interceptors must authenticate every method; check `max_receive_message_length`, reflection and `context.abort` paths that leak internals.'],
  websockets: ['FastAPI/Starlette/`websockets`: auth happens once at `accept()`; confirm the token is validated before accept, `Origin` is checked, and per-message authorization, size caps and rate limits exist. Look for broadcast managers that fan out private data by room id without membership checks.'],
  databases: [
    'SQLAlchemy/Django ORM: balance/credit/ticket/state changes must run in one transaction with `with_for_update()`/`select_for_update()` (or an atomic conditional UPDATE) in a canonical lock order; flag read-then-write across `await` points and separate sessions.',
    'Raw SQL: `text(f"...")`, `execute("..." % x)`, `.format`, `.raw()`/`.extra()`/`RawSQL` must use bound parameters; check `order_by`/column names taken from request data.',
    'Async correctness: shared module-level state mutated across coroutines, `asyncio.create_task` without error handling, and sessions shared between requests are race and data-leak sources.',
  ],
  crypto: [
    'python-jose/PyJWT: `decode` must pin `algorithms`, verify signature, `exp`, `aud` and `iss`; flag `options={"verify_signature": False}`, `verify=False`, HS/RS confusion and key material loaded from request data.',
    'Wallet auth (solders/PyNaCl/solana-py): confirm the signed message is the exact server-issued challenge (domain, nonce, expiry), nonce is single-use and stored atomically, and comparisons use `hmac.compare_digest`.',
    '`random`/`uuid1` must not generate tokens, nonces or seeds; require `secrets`/`os.urandom`. `pickle`, `marshal`, `yaml.load`, `jsonpickle` on untrusted input are code execution.',
  ],
  scopes_roles: ['Trace `Depends(get_current_user)`/permission dependencies into each handler and confirm the loaded object belongs to the caller (`owner_id == user.id`) before read or mutation, including admin/staff routes and background-job entry points.'],
  bots_economy: ['Celery/APScheduler/BackgroundTasks: confirm jobs are idempotent under retries, overlapping schedules and multiple workers, and that payouts/settlements use a unique key or conditional state transition.'],
  api_dto_abuse: ['FastAPI: every route should declare `response_model` (or return an explicit schema); flag returning ORM objects, `**row.__dict__`, `.dict()` of internal models, verbose `HTTPException(detail=...)` and debug tracebacks/`DEBUG=True` responses.'],
};

export function renderEcosystemLines(profile) {
  const eco = profile.ecosystems;
  if (!eco) return [];
  const row = (name, e, extra = '') => `- **${name}**: ${e.detected ? 'DETECTED' : 'absent'}${e.sourceFiles != null ? ` (${e.sourceFiles} production source files${e.testFiles ? `, ${e.testFiles} test/script files` : ''})` : ''}${extra}`;
  const py = eco.python;
  const declared = py.declaredVersion ? `; declared Python ${py.declaredVersion.version} (${py.declaredVersion.source})` : '';
  return [
    '## Detected Ecosystems',
    row('Python', py, `${py.frameworks.length ? `; frameworks: ${py.frameworks.join(', ')}` : ''}${declared}`),
    row('Node/TypeScript', eco.node, eco.node.frameworks.length ? `; frameworks: ${eco.node.frameworks.join(', ')}` : ''),
    row('Rust', eco.rust),
    `- **Solana program**: ${eco.solana.detected ? `DETECTED (${eco.solana.marks.slice(0, 4).join(', ')})` : 'absent'}`,
    `- Primary stack(s) by production source: ${eco.primary.join(', ') || 'none'}${eco.unsupported?.length ? `; no dedicated harness for: ${eco.unsupported.join(', ')}` : ''}`,
  ];
}

export function renderReviewPlansMarkdown(profile, surfaceFilter = '') {
  const filter = String(surfaceFilter || '').toUpperCase();
  const lines = [
    '# Stack Inventory & Source Security Review Plans',
    '',
    `Files scanned: ${profile.scannedFiles} | Active domains: ${profile.detectedStacks.join(', ') || 'none'}`,
    '',
    ...renderEcosystemLines(profile),
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
    const python = profile.ecosystems?.python?.detected ? PYTHON_CHECKS[d.id] || [] : [];
    for (const [idx, chk] of [...(REVIEW_CHECKS[d.id] || ['Inspect the cited source and existing tests; record evidence and coverage limits.']), ...python].entries()) {
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
          lines.push(`- \`${h.citation}\`${h.production === false ? ' (test/doc)' : ''} — \`${h.snippet.replace(/`/g, "'")}\``);
        }
      }
      lines.push('');
    }
  }

  return lines.join('\n') + '\n';
}

const SURFACE_TITLES = {
  S1: ['Identity, Scopes, Roles & Auth Planes', 'http, grpc, websockets, crypto, scopes_roles, api_dto_abuse'],
  S2: ['Input Handling, Protocol Parsing & Abuse', 'http, grpc, websockets, databases, api_dto_abuse'],
  S3: ['Business Logic, Bot/Economy Integrity, DB Locks & Crypto Custody', 'bots_economy, databases, crypto, scopes_roles'],
  S4: ['Secrets, Config, Infrastructure & Response DTO Exposure', 'api_dto_abuse, http, grpc'],
  S5: ['Dependencies, Lockfiles, CI & Verifiable Builds', 'crypto, http'],
  S6: ['Client, Web Surface, WebSockets & Economy Client Boundary', 'http, websockets, crypto, bots_economy, api_dto_abuse'],
};

const NODE_SURFACE = {
  S1: ['- Node: audit guards/middleware (`@UseGuards`, Express middleware order), session cookies (`__Host-`, `httpOnly`, `SameSite`, `Secure`), CSRF/Origin checks and gRPC/WebSocket auth.'],
  S2: ['- Node: audit `@ZodBody/@ZodQuery/@ZodParams`/schema validators, prototype pollution, `child_process.exec`, `eval`/`new Function`, template-string SQL, SSRF and `path.join(req.*)` sinks.'],
  S3: ['- Node: audit single-transaction execution under `FOR UPDATE` row locks (Prisma `$transaction`, TypeORM) in canonical lock order and check-then-act gaps.'],
  S4: ['- Node: audit `.env` handling, helmet/CSP/nginx headers, Dockerfiles and leaked internal fields in controller DTOs.'],
  S5: ['- Node: audit `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` advisories, lifecycle (`postinstall`) scripts and reachability.'],
  S6: ['- Node/browser: audit DOM XSS sinks, `postMessage` origin checks, CSP/SRI, CORS (`*` vs credentials) and WebSocket CSWSH.'],
};

const PYTHON_SURFACE = {
  S1: [
    '- Python: map every FastAPI/Starlette route to its auth `Depends(...)` (router- and route-level), Django/DRF `permission_classes`, Flask `before_request`/decorators; list routes with none.',
    '- Python: audit JWT handling (python-jose/PyJWT: pinned `algorithms`, signature, `exp`/`aud`/`iss`), session/cookie flags, CSRF for cookie auth, and wallet-signature challenge binding (single-use nonce, domain, expiry, `hmac.compare_digest`).',
    '- Python: for every handler taking an `*_id`/wallet, confirm the loaded ORM object belongs to the caller before read or write (IDOR); compare admin/staff dependency chains with player routes.',
  ],
  S2: [
    '- Python: audit Pydantic models (`extra="forbid"`, length/range bounds), `**model.dict()` mass assignment, `Body/Query/Form` defaults and file uploads (`python-multipart`) for size/type/path handling.',
    '- Python: audit SQL built with f-strings/`%`/`.format` into `execute()`/`text()`/`.raw()`/`.extra()`; `subprocess(..., shell=True)`, `os.system`, `eval`/`exec`, `pickle`/`marshal`/`yaml.load`, XML parsers without `defusedxml`, Jinja2 `autoescape=False`/`render_template_string`, SSRF via `requests`/`httpx`/`aiohttp` with request-controlled URLs, `open()`/`send_file` path traversal.',
  ],
  S3: [
    '- Python: audit money/credit/ticket/state transitions for single-transaction execution with `with_for_update()`/`select_for_update()` or conditional UPDATEs; read-then-write across `await`, multiple sessions, and Celery/APScheduler retries or overlapping workers (idempotency keys).',
    '- Python: audit async races (shared module state, `asyncio.create_task` fire-and-forget, in-process caches/locks that break with multiple workers), Decimal vs float money math, and rounding/overflow in payout code.',
  ],
  S4: [
    '- Python: audit settings/env handling (`pydantic-settings` defaults, hard-coded secrets, `DEBUG=True`, `ALLOWED_HOSTS`, `SECRET_KEY`), response models vs ORM objects, verbose `HTTPException` detail and tracebacks, logging of secrets/tokens, Dockerfile (root user, base image pinning) and uvicorn/gunicorn proxy-header trust.',
  ],
  S5: [
    '- Python: audit `requirements*.txt`, `pyproject.toml`, `poetry.lock`/`uv.lock`/`Pipfile.lock`: unpinned `>=` specifiers and missing hashes mean the build is not reproducible and advisory scans cannot resolve versions; check `--index-url`/`--extra-index-url`, `-e`/`git+` dependencies and CI pip usage. Treat PyPI advisory leads (osv-scanner) as reachability questions.',
  ],
  S6: [
    '- Python-served client surface: audit server-rendered templates (Jinja2 autoescape, `|safe`, `Markup`), CORS/CSP/security headers set by middleware, WebSocket endpoints (handshake auth, Origin, per-message authorization) and what API responses expose to the browser.',
  ],
};

const SOLANA_SURFACE = {
  S3: ['- Solana/Anchor: audit escrow invariants: `Signer` == stored authority, account owner checks, canonical PDA bumps, fixed CPI targets, `reload()` after CPI, closing/initialization and Merkle proof/root attestation rules. In `markdown_summary` add a dedicated "Solana program" paragraph: files reviewed, controls verified, and whether tests or builds actually ran.'],
  S6: ['- Solana: audit Solana Actions/Blinks (`/actions.json`, `/api/actions/*`) and wallet transaction signing flows.'],
  S5: ['- Solana: audit verifiable-build pinning (`cargo-build-sbf`, `solana-verify`) and RustSec advisories in `Cargo.lock`.'],
};

// With a profile, only the detected ecosystems' guidance is emitted; with none, every stack is included.
export function renderSurfaceSkillGuidance(surfaceCode, profile) {
  const code = /^S[1-6]$/i.test(String(surfaceCode)) ? String(surfaceCode).toUpperCase() : 'S1';
  const eco = profile?.ecosystems;
  const want = (name) => !eco || eco[name]?.detected;
  const [title, domains] = SURFACE_TITLES[code];
  const lines = [`### ${code} Skill Focus — ${title} (${domains})`];
  if (eco) lines.push(`Detected stack: ${eco.primary.join(', ') || 'unknown'}${eco.python?.frameworks?.length ? ` (Python frameworks: ${eco.python.frameworks.join(', ')})` : ''}${eco.solana?.detected ? '; Solana program present' : ''}. Do not apply checks for ecosystems that are absent.`);
  if (want('python')) lines.push(...PYTHON_SURFACE[code]);
  if (want('node')) lines.push(...NODE_SURFACE[code]);
  if (want('solana')) lines.push(...(SOLANA_SURFACE[code] || []));
  lines.push(
    '',
    '### Mandatory Cross-Cutting Skill Checks (Apply to Every Surface)',
    '1. **Scopes & Roles Misvalidation (IDOR / RBAC / Plane Separation)**: verify every handler that reads or mutates a resource by ID/wallet checks ownership against the authenticated identity, and that vertical privilege separation (admin vs player, guest/demo vs real wallet) holds.',
    '2. **Bot / Headless Automation & Economy Integrity**: ask whether a headless bot, script or sybil farm can break the product idea or drain the reward economy; verify server-side authoritative checks, replay/uniqueness, deadlines and revocation gates.',
    '3. **API Abuse & Response DTO / Enumeration Oracles**: inspect every response DTO and error message (e.g. "user already registered", distinct status codes); report if an API leaks account/resource existence or raw internal fields.',
  );
  return lines.join('\n');
}

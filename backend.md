# 🔴 Infinity Exams Backend — Production Audit & Fix Guide

> **Audit Date:** April 20, 2026  
> **Scope:** Full codebase — security vulnerabilities, performance bottlenecks, race conditions, and multi-instance readiness  
> **Priority Legend:** 🔴 Critical · 🟡 High · 🟢 Medium · ⚪ Low

---

## Table of Contents

1. [🔴 CRITICAL — Security Vulnerabilities](#1--critical--security-vulnerabilities)
2. [🔴 CRITICAL — Multi-Instance / Race Conditions](#2--critical--multi-instance--race-conditions)
3. [🟡 HIGH — Authentication & Authorization Flaws](#3--high--authentication--authorization-flaws)
4. [🟡 HIGH — Performance Bottlenecks](#4--high--performance-bottlenecks)
5. [🟢 MEDIUM — Data Integrity & Reliability](#5--medium--data-integrity--reliability)
6. [🟢 MEDIUM — Operational & Observability](#6--medium--operational--observability)
7. [⚪ LOW — Code Quality & DX](#7--low--code-quality--dx)

---

## 1. 🔴 CRITICAL — Security Vulnerabilities

### 1.1 Mass Assignment on All Mutation Endpoints

**Files affected:**
- `src/controllers/exam.controller.ts` — line 39: `{ id: nanoid(), ...body }`
- `src/controllers/exam.controller.ts` — line 503: `.set(body)` (updateExam)
- `src/controllers/studyRoom.controller.ts` — line 409: `.set(body)` (updateStudyRoom)
- `src/controllers/institute.controller.ts` — line 421: `.set(body)` (updateInstitute)
- `src/controllers/subscriptionPlan.controller.ts` — lines 45, 316, 333: `{ ...body, id: nanoid() }` and `.set(body)`
- `src/controllers/coupon.controller.ts` — line 37: `{ ...body, id: nanoid() }`, line 188: `.set(body)`
- `src/controllers/user.controller.ts` — line 414-445: `createAdminStaff` spreads entire body

**What's wrong:**  
`req.body` is directly spread into `.insert()` or `.set()` calls. An attacker can inject arbitrary fields like `isAdmin: true`, `role: "admin"`, `isActive: true`, `teacherAccountBalance: 999999`, etc.

**What to change:**  
Explicitly destructure and whitelist only the expected fields before passing them to the DB. Use a validation library like **Zod** or **Joi** to define strict schemas for each endpoint's input:

```typescript
// BEFORE (vulnerable)
const [data] = await db.update(exam).set(body).where(eq(exam.id, examId));

// AFTER (safe)
const { title, mcqs, type, examDuration, ... } = req.body; // explicit whitelist
const [data] = await db.update(exam).set({ title, mcqs, type, examDuration }).where(eq(exam.id, examId));
```

**Why:**  
Mass assignment is an OWASP Top-10 vulnerability. In production, a single malicious POST body could escalate privileges or corrupt financial data.

---

### 1.2 Global Rate Limiter is Disabled

**File:** `src/app.ts` — line 23

```typescript
// app.use(globalLimiter);  // ← COMMENTED OUT
```

**What's wrong:**  
Without a global rate limiter, any attacker can flood all endpoints with unlimited requests — causing denial of service, OTP brute-force, or DB exhaustion.

**What to change:**  
Uncomment the global limiter. Consider separate tiers:
- Global: `100 req/min/IP`
- Auth routes: already limited (3/min) ✅
- OTP routes: already limited (3/hour) ✅
- File upload routes: add a specific limiter (~5 req/min)

```typescript
app.use(globalLimiter);
```

**Why:**  
In a multi-instance setup behind a load balancer, rate limiting via Redis store (already configured) ensures limits are enforced globally across all instances.

---

### 1.3 Auth Middleware Not Applied to Most Routes

**File:** `src/routes/index.ts` — All route registrations

**What's wrong:**  
Looking at the routes, `authMiddleware` is only applied to 3 specific endpoints:
- `POST /exam/create-premium-exam`
- `POST /study-room/exams/create`
- (indirectly through those route files)

All other mutating routes (create/update/delete for exams, MCQs, users, study rooms, institutes, coupons, subscription plans, banners, etc.) are **completely unprotected**. Any anonymous request can:
- Create admin accounts (`POST /user/create/:role`)
- Delete any user (`DELETE /user/delete/:id`)
- Update any user's balance (`PUT /user/update/:id`)
- Create/delete exams, coupons, subscription plans, etc.

**What to change:**  
Apply `authMiddleware` globally to all routes except explicit public endpoints:

```typescript
// In routes/index.ts — apply auth globally
router.use(authMiddleware);

// Then create a separate public router for unauthenticated endpoints:
// - POST /user/create (registration)
// - POST /user/login
// - POST /user/verify-otp
// - GET /user/check-user-and-send-otp
// - GET /home (student/teacher homepage)
// - GET /health
```

Additionally, add **role-based authorization** checks. Right now even authenticated endpoints don't verify the user's role:

```typescript
// Example: Only admin/staff should be able to create exams
export const requireRole = (...roles: string[]) => (req, res, next) => {
  const userRole = req.user?.role;
  if (!roles.includes(userRole)) {
    throw new ApiError(403, "Forbidden");
  }
  next();
};
```

**Why:**  
This is the single most critical vulnerability. Without auth on mutation routes, your database can be arbitrarily modified by anyone on the internet.

---

### 1.4 OTP Logged to Console in Production

**File:** `src/services/sendOTP.service.ts` — line 23

```typescript
console.log(`Sending OTP ${otp} to ${phoneNumber}`);
```

**What's wrong:**  
OTP codes are printed to stdout. In production, logs are often aggregated (CloudWatch, GCP Logging, etc.) and accessible to operations staff. This leaks sensitive authentication codes.

**What to change:**  
Remove the OTP value from the log. Log only the phone number and a masked confirmation:

```typescript
logger.info(`[OTP] Sent to ${phoneNumber.slice(0, 4)}****`);
```

---

### 1.5 Expired Token Auto-Login Without Re-authentication

**File:** `src/controllers/user.controller.ts` — lines 691-721

**What's wrong:**  
In `getUserSession`, when the JWT is expired but the token still exists in the DB, the code **automatically issues a new token** without verifying the user's password. This effectively creates infinite sessions — once a user has a token, they never need to re-authenticate. If a token is stolen, the attacker has permanent access.

**What to change:**  
When a JWT is expired, the user should be required to re-authenticate. Return a 401 instead of auto-refreshing:

```typescript
if (!payload) {
  // Token expired — require re-login
  throw new ApiError(401, "Session expired. Please login again.");
}
```

If you want refresh token functionality, implement a proper **refresh token flow** with a separate, long-lived opaque token stored securely.

**Why:**  
Auto-refreshing expired tokens defeats the purpose of JWT expiration and creates a permanent backdoor if a token is ever compromised.

---

### 1.6 JWT Token Stored in Plain Text in Database

**File:** `src/controllers/user.controller.ts` — lines 76-83, `src/middlewares/auth.middleware.ts` — line 44

**What's wrong:**  
The full JWT token is stored as-is in the `account.token` column, and the auth middleware compares the incoming token with the stored one. If the database is ever breached, all active sessions are compromised — the attacker can use any stored token directly.

**What to change:**  
Store only a **hash** of the token (e.g., SHA-256) in the database. Compare hashes during authentication:

```typescript
import crypto from 'crypto';

const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
// Store tokenHash instead of token
// Compare crypto.createHash('sha256').update(incomingToken).digest('hex') === storedHash
```

---

### 1.7 `createAdminStaff` Allows Setting Any Role

**File:** `src/controllers/user.controller.ts` — lines 396-454, `src/routes/user.routes.ts` — line 38

**What's wrong:**  
The endpoint `POST /user/create/:role` has no authentication and accepts `body.role` which can be set to `"admin"`. The `:role` param in the route is unused in the controller — the role comes from `body.role`.

**What to change:**  
1. Add `authMiddleware` and `requireRole('admin')` to this route
2. Validate the role from body is only `"admin"` or `"staff"` (not `"teacher"` or `"student"` — those use `/create`)

---

## 2. 🔴 CRITICAL — Multi-Instance / Race Conditions

### 2.1 bKash Token Cached In-Memory (Not Shared Across Instances)

**File:** `src/utils/bkashAuth.ts` — lines 11-12

```typescript
let cachedToken: string | null = null;
let tokenExpiry: number = 0;
```

**What's wrong:**  
The bKash authentication token is cached in a module-level variable. In a multi-instance deployment (e.g., PM2 cluster mode, multiple containers), each instance fetches its own token independently. This causes:
1. **Redundant API calls** — N instances = N token requests
2. **Potential token invalidation** — bKash may invalidate the previous token when a new one is granted, causing other instances to use stale tokens

**What to change:**  
Store the bKash token in **Redis** with a TTL:

```typescript
export const getFreshBkashToken = async (): Promise<string> => {
  const cached = await redis.get('bkash:id_token');
  if (cached) return cached;

  // ... fetch new token from bKash API ...
  
  // Store with TTL slightly less than actual expiry
  const ttl = (data.expires_in || 3600) - 60;
  await redis.set('bkash:id_token', data.id_token, 'EX', ttl);
  return data.id_token;
};
```

**Why:**  
In a multi-instance setup, this ensures all instances share the same valid token and avoids race conditions with bKash's single-token policy.

---

### 2.2 Race Condition in XP Create/Update

**File:** `src/services/createOrUpdateXP.service.ts` — lines 23-43

**What's wrong:**  
The `createOrUpdateXP` function does a `findFirst` then conditionally `update` or `insert`. Between the read and write, another instance could insert a record for the same student/day, causing duplicate XP entries.

**What to change:**  
Use Postgres `INSERT ... ON CONFLICT DO UPDATE` (upsert) in a single atomic query:

```typescript
export const createOrUpdateXP = async (newXP: number, studentId: string) => {
  const today = new Date().toISOString().split("T")[0];
  
  await db.execute(sql`
    INSERT INTO xp (id, xp, student_id, created_at)
    VALUES (${nanoid(21)}, ${newXP}, ${studentId}, ${today}::date)
    ON CONFLICT (student_id, DATE(created_at))
    DO UPDATE SET xp = xp.xp + ${newXP}
  `);
};
```

You'll need a unique index on `(student_id, DATE(created_at))` for this to work.

**Why:**  
When multiple exam submissions arrive concurrently for the same student, the read-then-write pattern causes lost updates or duplicate records.

---

### 2.3 Race Condition in Exam Result Double-Submit

**File:** `src/controllers/exam.controller.ts` — lines 635-642, 662-670

**What's wrong:**  
The `saveExamResult` function checks if an exam is already `"completed"` via a `findFirst`, then updates. Between the check and update, another concurrent request could also pass the check, leading to **double XP awards** and conflicting result data.

**What to change:**  
Use a conditional `UPDATE ... WHERE status != 'completed'` and check the affected row count:

```typescript
const result = await db
  .update(premiumExam)
  .set({ correct, wrong, skipped, timeTaken, xp: correct, marks, studentAnswers, status: "completed" })
  .where(and(eq(premiumExam.id, examId), ne(premiumExam.status, "completed")))
  .returning({ id: premiumExam.id });

if (result.length === 0) throw new ApiError(409, "Exam already submitted");
```

**Why:**  
This is a classic TOCTOU (Time-Of-Check-Time-Of-Use) bug. In production with concurrent users, double-submit will corrupt exam data and inflate XP.

---

### 2.4 SSE Channel Map is In-Memory Only

**File:** `src/realtime/channels.ts` — line 7

```typescript
export const studyRoomChannels = new Map<string, Channel>();
```

**What's wrong:**  
The `studyRoomChannels` Map is local to each process. The Redis pub/sub system already addresses cross-instance broadcasting, but the local map **grows indefinitely** — channels are created but never cleaned up. Over time, this causes a memory leak.

**What to change:**  
Add cleanup logic to remove channels when they have zero sessions for a sustained period:

```typescript
channel.on("session-deregistered", () => {
  if (channel.sessionCount === 0) {
    setTimeout(() => {
      if (channel.sessionCount === 0) {
        studyRoomChannels.delete(studyRoomId);
        redis.del(REDIS_SESSION_KEY(studyRoomId) + `:${process.pid}`);
      }
    }, 60_000); // Clean up after 1 min of no sessions
  }
});
```

---

### 2.5 `setTimeout` for Critical Business Logic

**Files:**
- `src/controllers/user.controller.ts` — lines 326-349 (OTP after registration)
- `src/controllers/user.controller.ts` — lines 371-389 (OTP resend)
- `src/controllers/subscriptionPlan.controller.ts` — lines 443-463 (coupon validation)

**What's wrong:**  
`setTimeout` is used to defer OTP sending and coupon processing. Problems:
1. If the process crashes or restarts before the timeout fires, the OTP is never sent
2. Errors inside `setTimeout` are swallowed silently (they're not caught by the Express error handler)
3. In a multi-instance setup, the work is tied to a specific process

**What to change:**  
Use your existing **BullMQ queue** infrastructure instead of `setTimeout`:

```typescript
// Instead of setTimeout
await otpQueue.add('send-otp', { phoneNumber, otpCode }, { delay: 50 });
```

For coupon validation post-enrollment, just run it synchronously within the same request since it's critical business logic.

**Why:**  
BullMQ jobs survive process restarts, have built-in retry, and distribute across instances.

---

### 2.6 `deleteCacheByPrefix` Uses `SCAN` in Hot Paths

**File:** `src/utils/redisUtils.ts` — lines 86-109

**What's wrong:**  
`deleteCacheByPrefix` iterates over the entire Redis keyspace using `SCAN`. In a large Redis instance, this is O(N) and blocks the event loop with multiple round trips. It's called from nearly every mutating controller.

**What to change:**  
Use **Redis Sets** to track keys belonging to a prefix group, or use **Redis Hash** for namespaced caching:

```typescript
// Option A: Hash-based grouping
// Instead of: redis.set("exams:123", data)
// Use: redis.hset("exams", "123", data)
// Delete all: redis.del("exams")

// Option B: Track keys in a set
async function cacheSetWithGroup(group: string, key: string, value: any, ttl: number) {
  const pipeline = redis.pipeline();
  pipeline.set(key, JSON.stringify(value), 'EX', ttl);
  pipeline.sadd(`group:${group}`, key);
  pipeline.expire(`group:${group}`, ttl + 60);
  await pipeline.exec();
}

async function invalidateGroup(group: string) {
  const keys = await redis.smembers(`group:${group}`);
  if (keys.length > 0) {
    const pipeline = redis.pipeline();
    keys.forEach(k => pipeline.del(k));
    pipeline.del(`group:${group}`);
    await pipeline.exec();
  }
}
```

**Why:**  
`SCAN` with `MATCH` in a hot path degrades Redis performance as the dataset grows and blocks your Node.js event loop.

---

## 3. 🟡 HIGH — Authentication & Authorization Flaws

### 3.1 Auth Middleware Doesn't Attach User to Request

**File:** `src/middlewares/auth.middleware.ts` — line 51

**What's wrong:**  
After validating the JWT, the middleware calls `next()` but **doesn't attach the user payload to `req`**. Downstream controllers have no way to know who the authenticated user is. This means controllers can't enforce authorization (e.g., "can this user edit this exam?").

**What to change:**  
Attach the decoded user payload to the request:

```typescript
// After successful verification
(req as any).user = {
  id: userAccount.id,
  role: payload.user.role,
  // ...other fields
};
next();
```

---

### 3.2 Subscription Check Trusts Client-Sent `userRole`

**File:** `src/middlewares/subscriptionCheck.middleware.ts` — lines 9-13

```typescript
const { studentId, userRole } = req.body;
if (userRole === "teacher") return next(); // ← trusts client
```

**What's wrong:**  
The user's role is taken from `req.body`, which the client controls. Any student can bypass the subscription check by sending `userRole: "teacher"`.

**What to change:**  
Get the role from the authenticated user attached to the request (after fixing 3.1):

```typescript
const userRole = (req as any).user?.role;
if (userRole === "teacher") return next();
```

---

### 3.3 Logout Uses Unauthenticated Query Parameter

**File:** `src/controllers/user.controller.ts` — line 515, `src/routes/user.routes.ts` — line 31

```typescript
const id = req.query.userId;  // Anyone can log out anyone else
```

**What's wrong:**  
Logout is a GET request with `userId` as a query parameter, and has no authentication. Anyone can log out any user by knowing their ID.

**What to change:**  
1. Change to `POST /user/logout`
2. Add `authMiddleware`
3. Get userId from the JWT payload, not from query params

---

### 3.4 `updateUserPassword` Has No Auth and Bypasses Current Password Check

**File:** `src/controllers/user.controller.ts` — lines 593-631, `src/routes/user.routes.ts` — line 45

**What's wrong:**  
The endpoint `PUT /user/update-password` has **no auth middleware**. The `isCheckCurrentPassword` flag is controlled by the client — an attacker can set it to `false` and change any user's password by providing only their phone number:

```json
{
  "phone": "01700000000",
  "password": "newpass",
  "confirmPassword": "newpass",
  "isCheckCurrentPassword": false
}
```

**What to change:**  
1. Add `authMiddleware` to this route
2. **Always** require the current password for authenticated password changes
3. For password reset flow (via OTP), use a separate endpoint with a time-limited token

---

## 4. 🟡 HIGH — Performance Bottlenecks

### 4.1 Auth Middleware Hits DB on Every Single Request

**File:** `src/middlewares/auth.middleware.ts` — lines 30-36

**What's wrong:**  
Every authenticated request triggers a `db.query.account.findFirst()` to verify the token matches the stored one in the database. At scale, this means N DB queries per second just for auth validation.

**What to change:**  
Cache the token validation in Redis with a short TTL:

```typescript
const cacheKey = `auth:token:${incomingToken.slice(-16)}`;
const cached = await redis.get(cacheKey);

if (cached) {
  req.user = JSON.parse(cached);
  return next();
}

// ... DB lookup ...
await redis.set(cacheKey, JSON.stringify(userPayload), 'EX', 300); // 5 min
```

Invalidate on logout/password change (you already do `invalidateUserSessionCache`).

**Why:**  
This is the most-called code path in the entire application. Reducing it from a DB round-trip to a Redis round-trip will significantly reduce DB load.

---

### 4.2 Homepage Does 6 Parallel DB Queries on Every Cache Miss

**File:** `src/controllers/home.controller.ts` — lines 110-181

**What's wrong:**  
`getStudentHomeData` runs 6 concurrent queries on cache miss, including a complex leaderboard aggregation with `JOIN`, `GROUP BY`, `SUM`, and `ROW_NUMBER()`. The default cache TTL is from `config.redisTTL` (300s / 5 min). For a homepage that changes rarely, this is too aggressive.

**What to change:**  
1. Increase cache TTL for homepage data to **15-30 minutes**
2. Use background refresh: keep serving stale data while refreshing in the background
3. Pre-warm the cache on server startup

```typescript
await cacheSet(KEY, responseData, 60 * 15); // 15 minutes
```

---

### 4.3 `statisticsMCQ` Runs 5 Full Table Scans Concurrently

**File:** `src/controllers/mcq.controller.ts` — lines 697-810

**What's wrong:**  
The `statisticsMCQ` endpoint runs 5 separate `COUNT(*)` queries with `GROUP BY`, each scanning the entire `mcqs` table with joins. This is extremely expensive for large datasets and has **no caching**.

**What to change:**  
1. Add Redis caching with a reasonable TTL:
```typescript
const KEY = constructKey({ key: "mcq-statistics", req });
const cached = await cacheGet(KEY);
if (cached) return res.json(new ApiResponse(200, JSON.parse(cached)));
```
2. Invalidate when MCQs are created/updated
3. Consider maintaining a materialized view or summary table for statistics

---

### 4.4 `getAllMCQ` Runs a Second Full `COUNT(*)` Query

**File:** `src/controllers/mcq.controller.ts` — lines 296-299

**What's wrong:**  
After fetching paginated data with `LEFT JOIN` and complex conditions, a separate `COUNT(*)` query is executed on the same table with the same filters. For tables with millions of rows, this doubles the query time.

**What to change:**  
Use a window function to get the total in the same query:

```sql
SELECT *, COUNT(*) OVER() AS total_row FROM mcqs ...
```

Or use an estimated count for pagination when exact counts aren't critical:

```typescript
// Fast approximate count
const [{ estimate }] = await db.execute(
  sql`SELECT reltuples AS estimate FROM pg_class WHERE relname = 'mcqs'`
);
```

---

### 4.5 Database Connection Pool is Fixed at 20

**File:** `src/db/index.ts` — line 15

```typescript
max: 20, // Max connections per worker
```

**What's wrong:**  
With multiple instances (e.g., 4 PM2 workers × 20 = 80 connections), you can easily exceed your database's connection limit (Supabase free: 60, pro: 200). This leads to connection timeouts and crashes under load.

**What to change:**  
Calculate pool size based on available connections:

```typescript
const maxPoolPerWorker = Math.floor(
  (Number(process.env.DB_MAX_CONNECTIONS) || 80) / 
  (Number(process.env.CLUSTER_WORKERS) || 1)
);

export const client = postgres(connectionString, {
  prepare: false,
  max: maxPoolPerWorker,
  idle_timeout: 30,
  connect_timeout: 10,
});
```

---

### 4.6 `cacheGet` Parses JSON Twice

**File:** `src/utils/redisUtils.ts` — lines 48-66

**What's wrong:**  
`cacheGet` parses JSON to validate it (line 56), then every caller parses it again: `JSON.parse(cached)`. This doubles CPU usage for large payloads.

**What to change:**  
Return the parsed object directly from `cacheGet`:

```typescript
export async function cacheGet<T = any>(key: string): Promise<T | null> {
  const value = await redis.get(key);
  if (!value) return null;
  try {
    return JSON.parse(value) as T;
  } catch {
    await redis.del(key);
    return null;
  }
}
```

Then callers can use: `const cached = await cacheGet(KEY);` without re-parsing.

---

### 4.7 Health Check Creates New Redis Connections

**File:** `src/app.ts` — lines 121-123

```typescript
await redis.connect();
await redis.ping();
await redis.quit();
```

**What's wrong:**  
The health check endpoint creates a brand-new Redis connection, pings, then disconnects — on every call. This is wasteful and the `redis` instance from `lib/redis.ts` is already connected via ioredis (auto-connect). Calling `.connect()` and `.quit()` on the shared instance could break other parts of the application.

**What to change:**  
Use the existing shared Redis instance:

```typescript
try {
  const pong = await redis.ping();
  healthCheck.checks.redis = {
    status: pong === "PONG" ? "healthy" : "unhealthy",
    message: "Redis connected",
  };
} catch (error) { ... }
```

---

## 5. 🟢 MEDIUM — Data Integrity & Reliability

### 5.1 `bcrypt.hashSync` / `compareSync` Block the Event Loop

**File:** `src/utils/utils.ts` — lines 8-16

**What's wrong:**  
`bcrypt.hashSync` and `bcrypt.compareSync` are synchronous operations that block the Node.js event loop for 50-200ms per call (depending on salt rounds). During login or registration spikes, this causes all other requests to stall.

**What to change:**  
Use the async versions:

```typescript
export const genHashedPassword = async (password: string, salt = 10) => {
  return bcrypt.hash(password, salt);
};

export const compareHashedPassword = async (password: string, hashedPassword: string) => {
  return bcrypt.compare(password, hashedPassword);
};
```

Update all callers to `await` the result.

---

### 5.2 Coupon Validation Has TOCTOU Race Condition

**File:** `src/services/validateCoupon.service.ts` — lines 67-102

**What's wrong:**  
The flow is: check `maxUsage > 0` → check `alreadyUsed` → insert usage → decrement `maxUsage`. Two concurrent requests can both pass the checks before either writes, allowing:
1. A user to use the same coupon twice
2. `maxUsage` to go below zero

**What to change:**  
Use a single atomic transaction with a `SELECT ... FOR UPDATE`:

```typescript
await db.transaction(async (tx) => {
  // Lock the coupon row
  const [lockedCoupon] = await tx.execute(
    sql`SELECT * FROM coupons WHERE id = ${couponId} FOR UPDATE`
  );
  
  if (lockedCoupon.max_usage <= 0) throw new ApiError(400, "Coupon exhausted");
  
  // Check + insert usage atomically
  // ... rest of logic ...
});
```

---

### 5.3 `createOrUpdateInstituteXP` Updates Wrong Table

**File:** `src/services/createOrUpdateXP.service.ts` — line 70

```typescript
await db.update(xp)  // ← should be instituteXp
  .set({ xp: sql`${xp.xp} + ${newXP}` })
  .where(eq(instituteXp.id, existing.id));
```

**What's wrong:**  
When updating existing institute XP, the code updates the `xp` table instead of the `instituteXp` table. This is a direct bug that corrupts data.

**What to change:**  
```typescript
await db.update(instituteXp)
  .set({ xp: sql`${instituteXp.xp} + ${newXP}` })
  .where(eq(instituteXp.id, existing.id));
```

---

### 5.4 `checkStudentSubscriptionActiveStatus` Silently Swallows Errors

**File:** `src/utils/utils.ts` — line 75

```typescript
} catch (error) {}  // ← empty catch
```

**What's wrong:**  
If the DB query fails, the function returns `undefined`, which is falsy — so the student is treated as having no active subscription. Legitimate paying students could be denied access due to transient DB errors.

**What to change:**  
Log the error and re-throw, or return `true` as a safe default (prefer allowing over blocking):

```typescript
} catch (error) {
  logger.error({ error }, "Failed to check subscription status");
  throw error; // Let the caller handle it
}
```

---

### 5.5 `JSON.parse()` of `req.query` Strings Without Try-Catch

**File:** `src/controllers/mcq.controller.ts` — lines 585, 638-641

```typescript
if (mcqIds) baseConditions.push(inArray(mcqs.id, JSON.parse(mcqIds)));
const selectedTopicsData = JSON.parse(req.query.selectedTopicsData as string);
const programsData = JSON.parse(req.query.programsData as string);
```

**What's wrong:**  
If the query parameter is malformed JSON, `JSON.parse` throws and crashes the request with an unhandled error (or a generic 500). An attacker can trigger this intentionally.

**What to change:**  
Wrap in try-catch or validate before parsing:

```typescript
let parsedIds: string[];
try {
  parsedIds = JSON.parse(mcqIds);
  if (!Array.isArray(parsedIds)) throw new Error();
} catch {
  throw new ApiError(400, "Invalid mcqIds format");
}
```

---

### 5.6 Graceful Shutdown Doesn't Close Database Connections

**File:** `src/server.ts` — lines 25-47

**What's wrong:**  
The shutdown handler closes BullMQ workers and PostHog, but doesn't close the PostgreSQL connection pool or Redis connections. This can cause in-flight queries to be aborted and connection leaks.

**What to change:**  
Add database and Redis cleanup:

```typescript
import { client } from './db/index';
import { shutdownRedis } from './lib/redis';

async function shutdown(signal: string) {
  // ... existing code ...
  
  try {
    await client.end({ timeout: 5 });
    logger.info("Database connections closed");
  } catch (err) {
    logger.error({ err }, "Error closing database");
  }

  try {
    await shutdownRedis();
    logger.info("Redis connections closed");
  } catch (err) {
    logger.error({ err }, "Error closing Redis");
  }
  
  // ... process.exit(0) ...
}
```

---

## 6. 🟢 MEDIUM — Operational & Observability

### 6.1 `console.log` / `console.error` Used Instead of Logger

**Files affected (non-exhaustive):**
- `src/middlewares/errorHandler.middleware.ts` — lines 61, 72
- `src/middlewares/multer.middleware.ts` — line 15
- `src/middlewares/examController.middleware.ts` — line 23
- `src/controllers/exam.controller.ts` — lines 601-611
- `src/controllers/notification.controller.ts` — lines 58, 72, 83, 92
- `src/services/createOrUpdateXP.service.ts` — lines 46, 84
- `src/services/sendOTP.service.ts` — lines 22-23
- `src/controllers/fileUploadHandler.controller.ts` — lines 84-89, 124, 240
- `src/utils/bkashAuth.ts` — line 45

**What's wrong:**  
`console.log` bypasses the structured logger (`pino` via `LoggerFactory`), losing:
- JSON formatting for log aggregation
- Log levels
- Request context
- Timestamps

**What to change:**  
Replace all `console.log/error/warn` with `logger.info/error/warn` from `utils/logger/LoggerFactory`.

---

### 6.2 Morgan + Custom Logger = Double Logging

**File:** `src/app.ts` — lines 24-43

**What's wrong:**  
Both `morgan("dev")` (line 26) and the custom `requestLogger()` (line 24) plus the inline logger (lines 41-43) all log request information. This creates 3x the log output, wastes I/O, and makes log analysis harder.

**What to change:**  
Pick one logging strategy. In production, use only the structured `requestLogger()` and disable Morgan:

```typescript
if (process.env.NODE_ENV !== "production") {
  app.use(morgan("dev"));
}
app.use(requestLogger());
// Remove the inline logger middleware at lines 41-43
```

---

### 6.3 PostHog Telemetry on Every Request Adds Latency

**File:** `src/app.ts` — lines 46-83

**What's wrong:**  
Every single request triggers two PostHog captures (`api_request_started` + `api_request_completed`). Even with sampling (20-30%), the PostHog client still creates objects, checks the sample rate, and potentially makes HTTP calls. On high-traffic routes, this adds measurable latency.

**What to change:**  
1. Remove `api_request_started` — it adds no value over `api_request_completed`
2. Only capture for slow requests or errors:

```typescript
res.on("finish", () => {
  const durationMs = ...;
  // Only capture slow requests (>1s) or errors
  if (durationMs > 1000 || res.statusCode >= 400) {
    capturePosthogEvent("api_request_completed", { ... });
  }
});
```

---

## 7. ⚪ LOW — Code Quality & DX

### 7.1 Duplicate `isEdited` Condition

**File:** `src/controllers/studyRoom.controller.ts` — `getAllMCQForReviewer`  
**Actually in:** `src/controllers/mcq.controller.ts` — lines 326 and 348

```typescript
baseConditions.push(eq(mcqs.isEdited, true));   // line 326
// ... other conditions ...
baseConditions.push(eq(mcqs.isEdited, true));   // line 348 (exact duplicate)
```

**What to change:** Remove the duplicate at line 348.

---

### 7.2 `getUserStudyRooms` Returns `ApiError` as JSON Instead of Throwing

**File:** `src/controllers/studyRoom.controller.ts` — line 332

```typescript
if (!userId) return res.json(new ApiError(404, "Nothing found"));
```

**What's wrong:**  
`ApiError` is sent via `res.json()` instead of being thrown. This returns a 200 status with an error body, confusing clients.

**What to change:**  
```typescript
if (!userId) throw new ApiError(400, "User ID is required");
```

---

### 7.3 Multiple Redis Connections Created

**File:** `src/lib/redis.ts` — 2 connections, `src/lib/redisPubSub.ts` — 2 more via `duplicate()`

**What's wrong:**  
4 Redis connections per process are created at startup. With N worker processes, that's 4N connections to Redis.

**What to change:**  
This is acceptable for the current architecture (main, bullmq, pub, sub), but be aware of connection limits. Document the expected connection count and set Redis `maxclients` accordingly.

---

### 7.4 `.env` File in Repository Root

**File:** `.env` (1856 bytes), `.env.production` (1759 bytes)

**What's wrong:**  
Both `.env` files are present in the project root. If they're committed to Git, all secrets (DB credentials, API keys, JWT secrets, bKash credentials) are exposed in the repository history.

**What to change:**  
1. Verify `.env` and `.env.production` are in `.gitignore`
2. If they were ever committed, **rotate ALL secrets immediately**
3. Use environment-variable injection from your hosting platform (Railway, AWS Secrets Manager, etc.)

---

### 7.5 File Upload Has No Virus/Content Scanning

**Files:** `src/middlewares/multer.middleware.ts`, `src/controllers/fileUploadHandler.controller.ts`

**What's wrong:**  
Files are accepted based solely on MIME type checking, which is trivially spoofable. A malicious file with a faked MIME type could be uploaded and served.

**What to change:**  
1. Validate actual file content (magic bytes) not just MIME type
2. Set `Content-Disposition: attachment` on all served files
3. Consider running uploaded files through a virus scanner (ClamAV) for PDF uploads

---

## Summary Priority Matrix

| Priority | Count | Categories |
|----------|-------|------------|
| 🔴 Critical | 13 | Auth bypass, mass assignment, rate limit disabled, race conditions |
| 🟡 High | 7 | Performance bottlenecks, authorization flaws |
| 🟢 Medium | 9 | Data integrity, error handling, graceful shutdown |
| ⚪ Low | 5 | Code quality, logging, ops |

### Recommended Fix Order

1. **Immediately:** Enable global rate limiter (§1.2), add auth middleware to all routes (§1.3)
2. **This sprint:** Fix mass assignment (§1.1), fix password reset bypass (§3.4), fix XP bug (§5.3)
3. **Next sprint:** Move bKash token to Redis (§2.1), fix race conditions (§2.2, §2.3, §5.2)
4. **Ongoing:** Replace `console.log` with logger (§6.1), add input validation with Zod (§1.1)

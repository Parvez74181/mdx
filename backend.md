# 🔒 Security & Performance Audit – Production Fix Guide

> **Audit Date:** April 14, 2026  
> **Scope:** Full backend codebase (`infinity-exams-backend`)  
> **Methodology:** Manual source-code review of all routes, controllers, middleware, config, DB, services, and utilities

---

## Table of Contents

1. [🚨 CRITICAL – SQL Injection](#1--critical--sql-injection)
2. [🚨 CRITICAL – Missing Authentication & Authorization on Most Routes](#2--critical--missing-authentication--authorization-on-most-routes)
3. [🚨 CRITICAL – Global Rate Limiter Is Disabled](#3--critical--global-rate-limiter-is-disabled)
4. [🚨 CRITICAL – Graceful Shutdown Is Commented Out](#4--critical--graceful-shutdown-is-commented-out)
5. [🚨 CRITICAL – Error Handler Leaks Internal State to Clients](#5--critical--error-handler-leaks-internal-state-to-clients)
6. [🔴 HIGH – `updateExam` / `updateStudyRoom` / `updateInstitute` Accept Raw Body Spread](#6--high--updateexam--updatestudyroom--updateinstitute-accept-raw-body-spread)
7. [🔴 HIGH – Subscription Check Relies on Client-Sent `userRole`](#7--high--subscription-check-relies-on-client-sent-userrole)
8. [🔴 HIGH – Logout via GET with User-Supplied `userId`](#8--high--logout-via-get-with-user-supplied-userid)
9. [🔴 HIGH – `updateUserPassword` Has No Authentication Gate](#9--high--updateuserpassword-has-no-authentication-gate)
10. [🔴 HIGH – bKash Callback Open Redirect Vulnerability](#10--high--bkash-callback-open-redirect-vulnerability)
11. [🔴 HIGH – bKash Token Cached In-Memory (Cluster-Unsafe)](#11--high--bkash-token-cached-in-memory-cluster-unsafe)
12. [🔴 HIGH – OTP Logged to Console in Production](#12--high--otp-logged-to-console-in-production)
13. [🟠 MEDIUM – `express.json()` Has No Body Size Limit](#13--medium--expressjson-has-no-body-size-limit)
14. [🟠 MEDIUM – Health Check Creates a New Redis Client on Every Request](#14--medium--health-check-creates-a-new-redis-client-on-every-request)
15. [🟠 MEDIUM – Trusted Origins Include Development/LAN Addresses in Production](#15--medium--trusted-origins-include-developmentlan-addresses-in-production)
16. [🟠 MEDIUM – Auth Middleware Hits DB on Every Request (No Cache)](#16--medium--auth-middleware-hits-db-on-every-request-no-cache)
17. [🟠 MEDIUM – `deleteCacheByPrefix` Uses `SCAN` + `DEL` Without Pipeline](#17--medium--deletecachebyprefix-uses-scan--del-without-pipeline)
18. [🟠 MEDIUM – `file.originalname` Used Directly in Disk Filename](#18--medium--fileoriginalname-used-directly-in-disk-filename)
19. [🟠 MEDIUM – No `express.json()` Payload Validation (Zod/Joi)](#19--medium--no-expressjson-payload-validation-zodjoi)
20. [🟠 MEDIUM – `getUserSession` Auto-Refreshes Expired Tokens](#20--medium--getusersession-auto-refreshes-expired-tokens)
21. [🟡 LOW – Excessive `console.log` Calls in Production](#21--low--excessive-consolelog-calls-in-production)
22. [🟡 LOW – Empty `catch` Block in `checkStudentSubscriptionActiveStatus`](#22--low--empty-catch-block-in-checkstudentsubscriptionactiveatus)
23. [🟡 LOW – Postgres Client Has No Connection Pool Limits](#23--low--postgres-client-has-no-connection-pool-limits)
24. [🟡 LOW – Redis Has No Reconnect Strategy Configuration](#24--low--redis-has-no-reconnect-strategy-configuration)
25. [🟡 LOW – Hardcoded Cluster Worker Count](#25--low--hardcoded-cluster-worker-count)
26. [🟡 LOW – JWT Expiration is 15 Days (Very Long)](#26--low--jwt-expiration-is-15-days-very-long)
27. [🟡 LOW – `.env` and `.env.production` Not Listed in `.gitignore` Properly](#27--low--env-and-envproduction-not-listed-in-gitignore-properly)
28. [🟡 LOW – `setTimeout` Used for Critical Business Logic](#28--low--settimeout-used-for-critical-business-logic)
29. [📊 Performance Summary Table](#29--performance-summary-table)

---

## 1. 🚨 CRITICAL – SQL Injection

### Where
- `src/controllers/exam.controller.ts` → `createPremiumExam` (lines 66-69)
- `src/controllers/studyRoom.controller.ts` → `createStudyRoomExam` (lines 762-765)
- `src/controllers/mcq.controller.ts` → `getAllMCQForTeacherForCreatingManualExamInGroup` (lines 643-646)

### What's Wrong
User-supplied `programsData` array values are directly string-interpolated into raw SQL:

```ts
const programArraySql = programsData
  .filter((p: string | null) => p != null)
  .map((p: string) => `'${p}'`)   // ← NO ESCAPING
  .join(",");

// Then used in:
sql.raw(`ARRAY[${programArraySql}]::text[]`)
```

An attacker can send `programsData: ["'; DROP TABLE mcq; --"]` and execute arbitrary SQL.

### Why Fix
This is the **#1 most exploitable vulnerability** — a single crafted request can **read, modify, or delete the entire database**.

### How to Fix
Replace the raw interpolation with parameterized Drizzle queries:

```ts
// Option A: Use Drizzle's sql template for safe parameterization
const programArray = programsData.filter((p: string | null) => p != null);
// Then in the where clause:
sql`${mcqs.programs}::jsonb ?| ${sql.param(programArray)}::text[]`

// Option B: If param arrays don't work with ?| operator, 
// validate each value is a UUID/alphanumeric before interpolation:
const validId = /^[a-zA-Z0-9_-]+$/;
const sanitized = programsData.filter((p: string) => p && validId.test(p));
if (sanitized.length !== programsData.filter(Boolean).length) {
  throw new ApiError(400, "Invalid program ID format");
}
```

---

## 2. 🚨 CRITICAL – Missing Authentication & Authorization on Most Routes

### Where
Almost every route file in `src/routes/`:
- `mcq.routes.ts` — **ALL routes** (create, update, delete, bulk operations) have **no `authMiddleware`**
- `cq.routes.ts` — same
- `exam.routes.ts` — `createExam`, `updateExam`, `deleteExam`, `saveExamResult` are unprotected
- `user.routes.ts` — `updateUser`, `deleteUser`, `updateUserPassword`, `createAdminStaff` have no auth
- `institute.routes.ts` — **ALL routes** unprotected (create/update/delete institute, add/remove members)
- `notification.routes.ts` — mark-read, delete, broadcast are unprotected
- `studyRoom.routes.ts` — only `createStudyRoomExam` has auth; everything else is open
- `coupon.routes.ts` — create/update/delete coupons are unprotected
- `subscriptionPlan.routes.ts` — create/update/delete plans are unprotected
- `book.routes.ts`, `banner.routes.ts`, `chapter.routes.ts`, `class.routes.ts`, etc.

### What's Wrong
An **unauthenticated user** can:
- Create admin/staff accounts (`POST /api/v1/user/create/:role`)
- Delete any user (`DELETE /api/v1/user/delete/:id`)
- Change anyone's password (`PUT /api/v1/user/update-password`)
- Create/delete/modify exams, MCQs, study rooms, coupons, subscription plans

### Why Fix
Without authentication, **any anonymous internet user** has **full admin access** to the entire platform.

### How to Fix
1. Apply `authMiddleware` to ALL routes that modify data or access private data
2. Add a **role-based authorization middleware** that checks `req.user.role` after auth:

```ts
// New middleware: src/middlewares/authorize.middleware.ts
export const authorize = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!roles.includes(req.user.role)) {
      throw new ApiError(403, "Insufficient permissions");
    }
    next();
  };
};

// Usage in routes:
router.post("/create", authMiddleware, authorize("admin"), createExam);
router.delete("/delete/:id", authMiddleware, authorize("admin"), deleteExam);
router.put("/update/:id", authMiddleware, authorize("admin", "staff"), updateExam);
```

3. The current `authMiddleware` doesn't attach the user to `req` — fix it:
```ts
// In auth.middleware.ts, before next():
(req as any).user = { id: payload.sub, ...payload.user };
```

---

## 3. 🚨 CRITICAL – Global Rate Limiter Is Disabled

### Where
`src/app.ts` line 21:
```ts
// app.use(globalLimiter);   ← COMMENTED OUT
```

### What's Wrong
Without rate limiting, the API is vulnerable to:
- **Brute-force** password attacks (only `/login` has a limiter, but other endpoints are wide open)
- **Denial of Service (DoS)** — anyone can flood the server
- **Scraping** of all data

### Why Fix
Any attacker can send unlimited requests, exhausting database connections, Redis connections, and server memory.

### How to Fix
Uncomment the global limiter and adjust the limit to your needs:

```ts
app.use(globalLimiter); // Enable this in production
```

Consider separate limiters per route group (e.g., stricter limits for payment endpoints, lenient for reads).

---

## 4. 🚨 CRITICAL – Graceful Shutdown Is Commented Out

### Where
`src/server.ts` lines 43-59 — entire graceful shutdown block is commented out.

### What's Wrong
When the server receives `SIGTERM` or `SIGINT` (e.g., during a deployment restart):
- **In-flight requests are abruptly killed** — users making payments may have money deducted but no subscription
- **Database transactions are left incomplete** — data corruption risk
- **Open Redis connections are not closed** — connection pool exhaustion
- **BullMQ workers are not shut down** — jobs may be lost or duplicated

### Why Fix
In production (especially with financial transactions via bKash), an unclean shutdown can cause **money loss and data inconsistency**.

### How to Fix
Uncomment and properly implement:

```ts
async function shutdown(signal: string) {
  logger.info({ signal }, "Shutdown signal received");
  
  // Stop accepting new connections
  server.close(async () => {
    try {
      // Close Redis connections
      await redis.quit();
      await bullMQConnection.quit();
      
      // Close database connection
      await client.end();
      
      // Shut down workers
      await shutdownWorkers();
      
      logger.info("Server closed gracefully");
      process.exit(0);
    } catch (err) {
      logger.error("Error during shutdown", err);
      process.exit(1);
    }
  });

  // Force exit after 30 seconds
  setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 30_000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

process.on("unhandledRejection", (reason) => {
  logger.error({ reason }, "Unhandled rejection");
  // In production: log and continue, don't crash
});
```

---

## 5. 🚨 CRITICAL – Error Handler Leaks Internal State to Clients

### Where
`src/middlewares/errorHandler.middleware.ts` lines 50-56:

```ts
// Default to 500 for unhandled errors
console.error("Unhandled Error: ", err);
return res.status(500).json({
  success: false,
  message: "Internal Server Error",
  err: err,              // ← LEAKS FULL ERROR OBJECT
});
```

### What's Wrong
The raw `err` object is sent to the client. This can include:
- **Full stack traces** revealing file paths and line numbers
- **Database connection strings** if a DB error occurs
- **SQL query details** exposing table/column names
- **Environment variable values** in certain error types

### Why Fix
Leaked internals help attackers map your system, find vulnerable endpoints, and craft targeted exploits.

### How to Fix

```ts
return res.status(500).json({
  success: false,
  message: "Internal Server Error",
  // NEVER send the raw error in production:
  ...(process.env.NODE_ENV === "development" && { err: err.message }),
});
```

---

## 6. 🔴 HIGH – `updateExam` / `updateStudyRoom` / `updateInstitute` Accept Raw Body Spread

### Where
- `src/controllers/exam.controller.ts` → `updateExam` (line 500): `.set(body)`
- `src/controllers/studyRoom.controller.ts` → `updateStudyRoom` (line 397): `.set(body)`
- `src/controllers/institute.controller.ts` → `updateInstitute` (line 421): `.set(body)`
- `src/controllers/exam.controller.ts` → `createExam` (line 39): `.values({ id: nanoid(), ...body })`
- `src/controllers/subscriptionPlan.controller.ts` → lines 314-315: `.set(body)` directly

### What's Wrong
The entire `req.body` is passed directly to the database `set()` or `values()` call. An attacker can:
- Set fields not intended to be user-editable (e.g., `isDeleted: true`, `status: "completed"`, `createdBy: "hacker"`)
- Inject arbitrary columns

### Why Fix
This is a **mass assignment vulnerability**. The attacker controls what gets written to the database.

### How to Fix
Destructure and whitelist allowed fields:

```ts
// Instead of: .set(body)
const { title, examDuration, mcqs, isPublished } = req.body;
await db.update(exam).set({ title, examDuration, mcqs, isPublished }).where(...);
```

---

## 7. 🔴 HIGH – Subscription Check Relies on Client-Sent `userRole`

### Where
`src/middlewares/subscriptionCheck.middleware.ts` lines 9-13:

```ts
const { studentId, userRole } = req.body;

// Allow teachers without subscription check
if (userRole === "teacher") {
  return next();  // ← Any user can set userRole="teacher" to bypass
}
```

### What's Wrong
The `userRole` comes from `req.body`, which the client controls. Any student can send `{ userRole: "teacher" }` and **bypass the subscription check entirely** — accessing premium features for free.

### Why Fix
This completely defeats the subscription paywall.

### How to Fix
Get the role from the JWT token (set by `authMiddleware`), not from the request body:

```ts
const user = (req as any).user; // set by authMiddleware
if (user.role === "teacher") return next();
```

---

## 8. 🔴 HIGH – Logout via GET with User-Supplied `userId`

### Where
`src/routes/user.routes.ts` line 31:
```ts
router.get("/logout", logoutUser);
```

`src/controllers/user.controller.ts` lines 511-528:
```ts
const id = req.query.userId;
// ... clears token for that userId
```

### What's Wrong
1. **GET for a state-changing operation** — violates REST principles, can be triggered by `<img>` tags, link prefetchers, etc.
2. **No authentication** — anyone who knows a user ID can log them out
3. **userId from query params** — attacker can log out any user by visiting `/api/v1/user/logout?userId=TARGET_ID`

### Why Fix
This enables **targeted session denial** — an attacker can continuously log out administrators or paying users.

### How to Fix
```ts
// 1. Change to POST
router.post("/logout", authMiddleware, logoutUser);

// 2. Use the authenticated user's ID, not query params
const id = (req as any).user.id;
```

---

## 9. 🔴 HIGH – `updateUserPassword` Has No Authentication Gate

### Where
`src/routes/user.routes.ts` line 45:
```ts
router.put("/update-password", updateUserPassword);
```

`src/controllers/user.controller.ts` lines 593-607:
```ts
const { password, confirmPassword, phone: phoneNumber } = req.body;
// No auth check, no old-password check
const hashedPassword = genHashedPassword(password);
await db.update(account).set({ password: hashedPassword, token: null })
  .where(eq(account.phoneNumber, phoneNumber));
```

### What's Wrong
Anyone who knows a user's phone number can **reset their password** without authentication, without knowing the old password, and without OTP verification.

### Why Fix
This is a **complete account takeover** vulnerability.

### How to Fix
1. Add `authMiddleware` to the route
2. Verify the old password before changing (or require a valid OTP session token)
3. Only allow the authenticated user to change their own password:

```ts
router.put("/update-password", authMiddleware, updateUserPassword);

// In controller:
const id = (req as any).user.id;
const { oldPassword, password, confirmPassword } = req.body;
const user = await db.query.account.findFirst({ where: eq(account.id, id) });
if (!compareHashedPassword(oldPassword, user.password)) {
  throw new ApiError(401, "Current password is incorrect");
}
```

---

## 10. 🔴 HIGH – bKash Callback Open Redirect Vulnerability

### Where
`src/controllers/bkash.controller.ts` lines 102-103, 226-227:
```ts
return res.redirect(
  `${BKASH_CONFIG.FRONTEND_URL}/payment/error?status=${status}`
);
// ... and:
return res.redirect(
  `${BKASH_CONFIG.FRONTEND_URL}/payment/error?message=${data.statusMessage}`
);
```

### What's Wrong
The `status` and `data.statusMessage` values come from the bKash callback query and response. If an attacker crafts a callback URL with a malicious `status` parameter containing newlines or special chars, it could lead to **header injection** or **reflected XSS** via the redirect URL.

### Why Fix
Redirect URLs should never include unsanitized external input.

### How to Fix
- URL-encode all dynamic segments
- Validate `status` against an allow-list (`success`, `cancel`, `failure`)

```ts
const VALID_STATUSES = ["success", "cancel", "failure"];
const safeStatus = VALID_STATUSES.includes(status as string) ? status : "unknown";
return res.redirect(
  `${BKASH_CONFIG.FRONTEND_URL}/payment/error?status=${encodeURIComponent(safeStatus as string)}`
);
```

---

## 11. 🔴 HIGH – bKash Token Cached In-Memory (Cluster-Unsafe)

### Where
`src/utils/bkashAuth.ts` lines 11-12:
```ts
let cachedToken: string | null = null;
let tokenExpiry: number = 0;
```

### What's Wrong
With `cluster` mode (2 workers in `server.ts`), each worker has its own memory. This means:
- **Worker 1** may cache a token while **Worker 2** doesn't have one
- Under load, you're making **2x more token requests** to bKash than necessary
- If bKash has rate limits, you might get blocked

### Why Fix
Wastes API calls and introduces race conditions in clustered production.

### How to Fix
Cache the bKash token in **Redis** instead:

```ts
import redis from "lib/redis";

export const getFreshBkashToken = async (): Promise<string> => {
  const cached = await redis.get("bkash:id_token");
  if (cached) return cached;

  const { data } = await axios.post(/* ... */);
  
  if (data?.id_token) {
    const ttl = (data.expires_in || 3600) - 60; // 1-minute buffer
    await redis.set("bkash:id_token", data.id_token, "EX", ttl);
    return data.id_token;
  }
  throw new ApiError(401, "Failed to authenticate with bKash");
};
```

---

## 12. 🔴 HIGH – OTP Logged to Console in Production

### Where
`src/services/sendOTP.service.ts` lines 22-23:
```ts
console.log("Response:", data);
console.log(`Sending OTP ${otp} to ${phoneNumber}`);
```

### What's Wrong
The OTP is **printed to stdout** in production. Anyone with server log access (or a log aggregator) can see every OTP and use them to:
- Complete someone else's registration
- Reset anyone's password

### Why Fix
OTP codes are secrets. Logging them defeats the purpose of OTP verification.

### How to Fix
Remove or guard with environment check:
```ts
if (process.env.NODE_ENV === "development") {
  console.log(`[DEV] OTP ${otp} → ${phoneNumber}`);
}
// In production, only log success/failure — never the code itself
```

---

## 13. 🟠 MEDIUM – `express.json()` Has No Body Size Limit

### Where
`src/app.ts` line 26:
```ts
app.use(express.json());
```

### What's Wrong
Default Express body parser accepts up to **100 KB** in Express 5, but it's still wise to set explicit limits. With bulk MCQ creation (`createMCQ` accepts arrays), an attacker could send extremely large payloads.

### Why Fix
Prevents memory exhaustion/DoS from oversized request bodies.

### How to Fix
```ts
app.use(express.json({ limit: "2mb" })); // Set appropriate limit for your bulk operations
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
```

---

## 14. 🟠 MEDIUM – Health Check Creates a New Redis Client on Every Request

### Where
`src/app.ts` lines 80-85:
```ts
const redis = require("redis").createClient({ url: process.env.REDIS_URL });
await redis.connect();
await redis.ping();
await redis.quit();
```

### What's Wrong
Each `/health` request:
1. Creates a brand new Redis TCP connection
2. Sends a PING
3. Closes the connection

Under monitoring (e.g., Kubernetes with 10s health checks), this is **6 new connections per minute per worker** — 12 total with 2 workers.

### Why Fix
Connection churn strains Redis and adds latency to health checks.

### How to Fix
Reuse the existing `redis` instance from `lib/redis.ts`:

```ts
import redis from "./lib/redis";

// In health check:
try {
  await redis.ping();
  healthCheck.checks.redis = { status: "healthy", message: "Redis connected" };
} catch (error) {
  healthCheck.checks.redis = { status: "unhealthy", message: "Redis ping failed" };
}
```

---

## 15. 🟠 MEDIUM – Trusted Origins Include Development/LAN Addresses in Production

### Where
`src/data/trustedOrigins.ts` lines 6-30:
```ts
"http://localhost:3000",
"http://localhost:3001",
"http://192.168.0.100:3000",
// ... many more LAN IPs
```

### What's Wrong
These development origins are **always** included regardless of `NODE_ENV`. In production, this unnecessarily widens the CORS surface.

### Why Fix
In production, CORS should only allow your actual domains.

### How to Fix
```ts
const productionOrigins = [
  "https://infinityexams.com",
  "https://admin.infinityexams.com",
  "https://www.infinityexams.com",
  "https://www.admin.infinityexams.com",
];

const devOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  // ... etc
];

const trustedOrigins =
  process.env.NODE_ENV === "production"
    ? productionOrigins
    : [...productionOrigins, ...devOrigins];
```

---

## 16. 🟠 MEDIUM – Auth Middleware Hits DB on Every Request (No Cache)

### Where
`src/middlewares/auth.middleware.ts` lines 30-36:

```ts
const userAccount = await db.query.account.findFirst({
  where: eq(account.id, payload.sub as string),
  columns: { id: true, token: true },
});
```

### What's Wrong
Every authenticated request triggers a **database query** to verify the token. With 100 concurrent users making 10 requests each, that's **1,000 DB queries** just for authentication.

### Why Fix
Database is the bottleneck. Auth should be fast.

### How to Fix
Cache the token→user mapping in Redis with a short TTL (e.g., 5 minutes):

```ts
const cacheKey = `auth:${payload.sub}`;
let cachedToken = await redis.get(cacheKey);

if (!cachedToken) {
  const userAccount = await db.query.account.findFirst({ /* ... */ });
  if (!userAccount) throw new ApiError(401, "Account not found");
  await redis.set(cacheKey, userAccount.token, "EX", 300); // 5 min cache
  cachedToken = userAccount.token;
}

if (cachedToken !== incomingToken) {
  throw new ApiError(401, "Session invalidated");
}
```

Remember to invalidate this key on logout/password-change.

---

## 17. 🟠 MEDIUM – `deleteCacheByPrefix` Uses `SCAN` + `DEL` Without Pipeline

### Where
`src/utils/redisUtils.ts` lines 41-58:
```ts
const [nextCursor, keys] = await redis.scan(cursor, "MATCH", `${pattern}*`, "COUNT", 100);
if (keys.length > 0) {
  await redis.del(keys);
}
```

### What's Wrong
Each iteration sends individual `SCAN` + `DEL` commands. With many keys, this is slow and creates **many round-trips** to Redis.

### Why Fix
For large cache invalidation (e.g., `study-rooms:*`), this can take seconds and block the event loop.

### How to Fix
Use Redis pipeline for batch operations:

```ts
export async function deleteCacheByPrefix(pattern: string) {
  let cursor = "0";
  do {
    const [nextCursor, keys] = await redis.scan(cursor, "MATCH", `${pattern}*`, "COUNT", 200);
    if (keys.length > 0) {
      const pipeline = redis.pipeline();
      keys.forEach(key => pipeline.del(key));
      await pipeline.exec();
    }
    cursor = nextCursor;
  } while (cursor !== "0");
}
```

---

## 18. 🟠 MEDIUM – `file.originalname` Used Directly in Disk Filename

### Where
`src/middlewares/multerForAIHandler.middleware.ts` line 13:
```ts
cb(null, Date.now() + "-" + file.originalname);
```

### What's Wrong
`file.originalname` is user-controlled. A filename like `../../../etc/cron.d/evil` could potentially escape the upload directory (path traversal). While `multer` does some sanitization, relying on it is fragile.

### Why Fix
Never trust user-supplied filenames on disk.

### How to Fix
```ts
import { nanoid } from "nanoid";
import path from "node:path";

filename: (req, file, cb) => {
  const ext = path.extname(file.originalname) || ".pdf";
  const safe = ext.replace(/[^.a-zA-Z0-9]/g, ""); // sanitize extension
  cb(null, `${Date.now()}-${nanoid()}${safe}`);
},
```

---

## 19. 🟠 MEDIUM – No `express.json()` Payload Validation (Zod/Joi)

### Where
All controllers accept `req.body` and `req.query` without schema validation.

### What's Wrong
Controllers trust that `req.body` has the correct shape. Missing fields cause runtime errors or silent bugs. For example:
- `createMCQ` does `body.map(...)` — crashes if body is not an array
- `createPayment` accesses `amount` without type checking
- `loginUser` doesn't validate password length/format

### Why Fix
Without validation, the API accepts malformed data, leading to crashes, silent data corruption, and security bypasses.

### How to Fix
Add `zod` for request validation:

```bash
npm install zod
```

```ts
// src/validators/user.validator.ts
import { z } from "zod";

export const loginSchema = z.object({
  phoneNumber: z.string().min(11).max(15),
  password: z.string().min(6).max(100),
  iin: z.string().optional(),
});

// In controller:
const parsed = loginSchema.parse(req.body); // throws ZodError if invalid
```

---

## 20. 🟠 MEDIUM – `getUserSession` Auto-Refreshes Expired Tokens

### Where
`src/controllers/user.controller.ts` lines 660-699:

When JWT verification fails (expired token), the code:
1. Decodes the expired token **without verification**
2. Looks up the user by the expired token in DB
3. Issues a brand new **valid** token

### What's Wrong
This means **expired tokens never truly expire**. An attacker who steals an old token can always get a fresh one. This defeats the purpose of JWT expiration.

### Why Fix
Token expiration is a security boundary. If expired tokens auto-refresh without additional verification (like a refresh token flow), there's no way to invalidate compromised sessions by waiting for expiry.

### How to Fix
Remove the auto-refresh on expired tokens. Instead, implement a proper **refresh token** flow:
1. At login, issue both an **access token** (short-lived, 15min) and a **refresh token** (long-lived, stored in DB)
2. When the access token expires, require the client to call `/refresh-token` with the refresh token
3. Validate the refresh token before issuing a new access token

---

## 21. 🟡 LOW – Excessive `console.log` Calls in Production

### Where
Throughout the entire codebase — > 40 instances of `console.log` in controllers and middleware:

- `examController.middleware.ts`: `console.log(findExam)`
- `multer.middleware.ts`: `console.log(file)`
- `bkash.controller.ts`: `console.log(data)`
- `exam.controller.ts`: `console.log(type, examId, ...)`
- `aiq.controller.ts`: `console.log(response.usageMetadata)`
- `notification.controller.ts`: `console.log("Cache hit: ", KEY)`

### What's Wrong
- Wastes CPU cycles on serialization
- Potentially leaks sensitive data (file metadata, payment data, exam answers)
- Clutters production logs making real issues hard to find

### Why Fix
Clean logs improve debugging and reduce information leakage.

### How to Fix
1. Replace all `console.log` with the existing `logger` (`utils/logger/LoggerFactory`)
2. Use appropriate log levels (`logger.debug()` for dev, `logger.info()` for production events)
3. Remove all debug console.log calls before deploy

---

## 22. 🟡 LOW – Empty `catch` Block in `checkStudentSubscriptionActiveStatus`

### Where
`src/utils/utils.ts` line 75:
```ts
} catch (error) {}   // ← SILENTLY SWALLOWS ALL ERRORS
```

### What's Wrong
If the database query fails (connection timeout, pool exhaustion), the function returns `undefined` instead of `false`. Depending on how the caller checks the return value, this could **grant free access** during database outages.

### Why Fix
Silent error swallowing masks production issues.

### How to Fix
```ts
} catch (error) {
  logger.error("Subscription check failed", error);
  return false; // Fail closed — deny access on error
}
```

---

## 23. 🟡 LOW – Postgres Client Has No Connection Pool Limits

### Where
`src/db/index.ts` line 13:
```ts
export const client = postgres(connectionString, { prepare: false });
```

### What's Wrong
No `max` connections specified. With 2 cluster workers, each creates its own pool with default limits. Under load, this can exhaust the database connection limit (typically 100 for managed Postgres/Supabase).

### Why Fix
Connection exhaustion causes **all queries to fail**, taking down the entire platform.

### How to Fix
```ts
export const client = postgres(connectionString, {
  prepare: false,
  max: 20,            // Max connections per worker (adjust based on DB plan)
  idle_timeout: 30,   // Close idle connections after 30s
  connect_timeout: 10,// Fail fast if DB is unreachable
});
```

---

## 24. 🟡 LOW – Redis Has No Reconnect Strategy Configuration

### Where
`src/lib/redis.ts`:
```ts
const redis = new Redis(config.redisUrl);
```

### What's Wrong
Default `ioredis` reconnect strategy retries indefinitely with exponential backoff. If Redis goes down temporarily, pending commands queue up in memory and can cause the Node.js process to run out of memory.

### Why Fix
Prevents OOM crashes during Redis outages.

### How to Fix
```ts
const redis = new Redis(config.redisUrl, {
  maxRetriesPerRequest: 3,
  retryStrategy(times) {
    if (times > 10) return null; // stop retrying after 10 attempts
    return Math.min(times * 200, 5000); // max 5s between retries
  },
  enableOfflineQueue: false, // fail fast if Redis is down
});
```

---

## 25. 🟡 LOW – Hardcoded Cluster Worker Count

### Where
`src/server.ts` lines 10-11:
```ts
// const numCPUs = os.availableParallelism();
const numCPUs = 2;
```

### What's Wrong
Hardcoded to 2 workers regardless of the server's actual CPU count. On a 4-core machine, you're only using 50% capacity. On a 1-core machine, you're oversubscribing.

### Why Fix
Production servers should scale workers to CPU count automatically.

### How to Fix
```ts
const numCPUs = process.env.WEB_CONCURRENCY
  ? parseInt(process.env.WEB_CONCURRENCY)
  : os.availableParallelism();
```

---

## 26. 🟡 LOW – JWT Expiration is 15 Days (Very Long)

### Where
`src/controllers/user.controller.ts` line 71:
```ts
.setExpirationTime("15d")
```

### What's Wrong
If a token is compromised:
- The attacker has **15 days** of unrestricted access
- Combined with the auto-refresh in `getUserSession` (Issue #20), compromised tokens effectively **never expire**

### Why Fix
Shorter token lifetimes reduce the window of exposure for stolen credentials.

### How to Fix
- Access token: **1-4 hours**
- Refresh token: **7-15 days** (stored securely, rotated on use)

```ts
.setExpirationTime("4h"); // Access token
```

---

## 27. 🟡 LOW – `.env` and `.env.production` Not Listed in `.gitignore` Properly

### Where
`.gitignore` lines 73-75:
```
.env*
.env.test
.env.production
```

### What's Wrong
The pattern `.env*` does match both `.env` and `.env.production`, but the explicit listing of `.env.production` is redundant and confusing. More importantly, the `.env` and `.env.production` files **currently exist in the repo** (they're in the project directory), which suggests they might have been committed before the gitignore was added.

### Why Fix
If these files were ever committed, secrets (DB passwords, API keys, JWT secrets) are in the git history.

### How to Fix
1. Verify they're not tracked: `git ls-files .env .env.production`
2. If tracked, remove from git history: `git rm --cached .env .env.production`
3. Rotate ALL secrets that were ever in those files (DB password, JWT secret, bKash keys, API keys)

---

## 28. 🟡 LOW – `setTimeout` Used for Critical Business Logic

### Where
- `src/controllers/user.controller.ts` lines 323-346 — OTP sending after registration
- `src/controllers/user.controller.ts` lines 368-386 — OTP resend
- `src/controllers/subscriptionPlan.controller.ts` lines 442-462 — Coupon validation after subscription

### What's Wrong
`setTimeout` runs **outside** any error boundary. If the async operation inside fails:
- No retry mechanism
- No error propagation to the user
- In cluster mode, if the worker dies during the timeout, the operation is **permanently lost**

### Why Fix
OTP delivery failure means the user can never verify their account. Coupon validation failure means discounts aren't applied.

### How to Fix
Use BullMQ (which is already installed and configured!) to handle these as reliable background jobs:

```ts
// Instead of setTimeout, dispatch to a queue:
await otpQueue.add("send-otp", { phoneNumber, otpCode }, {
  attempts: 3,
  backoff: { type: "exponential", delay: 1000 },
});
```

---

## 29. 📊 Performance Summary Table

| Issue | Severity | Impact | Effort |
|-------|----------|--------|--------|
| SQL Injection in `programsData` | 🚨 CRITICAL | Full DB compromise | Low |
| Missing auth on most routes | 🚨 CRITICAL | Full API takeover | Medium |
| Global rate limiter disabled | 🚨 CRITICAL | DoS vulnerability | Trivial |
| Graceful shutdown disabled | 🚨 CRITICAL | Data corruption on deploy | Low |
| Error handler leaks internals | 🚨 CRITICAL | Information disclosure | Trivial |
| Raw body spread in updates | 🔴 HIGH | Mass assignment | Low |
| Subscription check bypass via `userRole` | 🔴 HIGH | Premium feature theft | Trivial |
| Logout via GET + no auth | 🔴 HIGH | Session denial attacks | Low |
| Password change without auth | 🔴 HIGH | Account takeover | Low |
| bKash redirect injection | 🔴 HIGH | Open redirect/XSS | Low |
| bKash token in-memory cache | 🔴 HIGH | Race conditions in cluster | Low |
| OTP logged in production | 🔴 HIGH | OTP leakage | Trivial |
| No JSON body size limit | 🟠 MEDIUM | Memory DoS | Trivial |
| Health check creates Redis clients | 🟠 MEDIUM | Connection churn | Low |
| Dev origins in production CORS | 🟠 MEDIUM | CORS bypass | Low |
| Auth middleware no cache | 🟠 MEDIUM | DB bottleneck | Low |
| `SCAN`+`DEL` without pipeline | 🟠 MEDIUM | Slow cache flush | Low |
| Unsafe filename on disk | 🟠 MEDIUM | Path traversal risk | Trivial |
| No input validation (Zod) | 🟠 MEDIUM | Crashes & data corruption | Medium |
| Auto-refresh expired tokens | 🟠 MEDIUM | Tokens never expire | Medium |
| Excessive `console.log` | 🟡 LOW | Info leak + noise | Low |
| Silent `catch` block | 🟡 LOW | Hides failures | Trivial |
| No DB pool limits | 🟡 LOW | Connection exhaustion | Trivial |
| No Redis reconnect config | 🟡 LOW | OOM on Redis outage | Trivial |
| Hardcoded worker count | 🟡 LOW | Poor CPU utilization | Trivial |
| 15-day JWT | 🟡 LOW | Long exposure window | Low |
| `.env` possibly committed | 🟡 LOW | Secret exposure | Low |
| `setTimeout` for background work | 🟡 LOW | Lost jobs | Medium |

---

> **Recommended Fix Order:**  
> 1. SQL Injection (#1) — fix immediately  
> 2. Authentication on routes (#2) — fix immediately  
> 3. Uncomment rate limiter (#3) — one line change  
> 4. Enable graceful shutdown (#4) — critical for deploys  
> 5. Fix error handler leakage (#5) — one line change  
> 6. Password change auth (#9) — account takeover risk  
> 7. OTP logging (#12) — remove two lines  
> 8. Fix all HIGH issues in order  
> 9. Address MEDIUM issues  
> 10. Clean up LOW issues

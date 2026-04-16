# Product Security & Performance Audit Report

This document outlines critical vulnerabilities and performance bottlenecks discovered in the Infinity Exams Backend and provides actionable remediation strategies for production readiness.

## 1. Critical Security Vulnerabilities (High Priority)

### 1.1. Missing Authentication & Authorization on Sensitive Routes
**Issue:** Many administrative and sensitive routes in `src/routes/index.ts` (e.g., `/user/delete/:id`, `/user/all`, `/mcq/create`, `/bkash/refund`) do not have `authMiddleware` or role-based checks applied.
**Risk:** Unauthorized users or attackers can delete users, access private data, or manipulate questions and payments.
**Fix:**
- Apply `authMiddleware` to all routes except public ones (login, signup, health).
- Implement `roleCheckMiddleware(['admin', 'staff'])` for administrative actions.
**Why:** Ensures only authenticated and authorized users can access sensitive endpoints.

### 1.2. Role Escalation & Mass Assignment in User Management
**Issue:** In `src/controllers/user.controller.ts`, the `createUser` and `updateUser` functions take `role`, `isReviewer`, and `isApprover` directly from `req.body`.
**Risk:** A regular user can register as an `admin` or grant themselves reviewer privileges by modifying the JSON payload.
**Fix:**
- Use a "Whitelist" approach for `req.body` (only allow specific fields like `name`, `email`).
- Role changes should only be permitted by existing admins via a dedicated endpoint.
- Use a validation library like **Zod** to enforce strict schemas.
**Why:** Prevents attackers from elevating their status within the system.

### 1.3. Insecure Password Reset Logic
**Issue:** `updateUserPassword` in `user.controller.ts` updates a password based only on a phone number passed in the body, without verifying if an OTP was recently successfully validated for that session.
**Risk:** An attacker can change any user's password if they know their phone number.
**Fix:**
- Require a verification token (stored in Redis after OTP success) to be passed with the password reset request.
**Why:** Prevents account takeover through simple phone number enumeration.

### 1.4. Payment Security (Price & User Manipulation)
**Issue:** In `bkash.controller.ts`, `createPayment` trusts the `amount` and `userId` sent from the client.
**Risk:** Users can pay 1 BDT for a 1000 BDT plan, or pay for their own account and credit it to another user's ID.
**Fix:**
- Fetch the expected price from the database using the `targetId` (plan ID) and use *that* for the bKash request.
- Use `req.user.id` (from auth middleware) instead of `req.body.userId`.
**Why:** Prevents financial loss and data integrity issues.

---

## 2. Performance Issues & Bottlenecks

### 2.1. Inefficient Health Check
**Issue:** The `/health` route in `app.ts` creates and closes a NEW Redis connection on every single request.
**Risk:** High overhead and potential connection pool exhaustion under frequent monitoring.
**Fix:**
- Use the existing `redis` client instance and check its status (e.g., `redis.status === 'ready'`) or call `ping()` without connecting/quitting.
**Why:** Reduces latency and resource consumption.

### 2.2. Expensive Aggregations in MCQ Lists
**Issue:** `getAllMCQ` performs a `LEFT JOIN` and `COUNT` with `GROUP BY` on every list fetch to get review counts.
**Risk:** As the `mcq_reviews` table grows to millions of rows, these queries will become extremely slow.
**Fix:**
- **Denormalize:** Add `total_ok` and `total_not_ok` columns directly to the `mcqs` table and update them as reviews come in.
- **Caching:** Use Redis to cache the MCQ lists for common filter combinations.
**Why:** Increases response speed for the most visited pages.

### 2.3. Missing Global Rate Limiting
**Issue:** `globalLimiter` is commented out in `app.ts`.
**Risk:** Susceptibility to Denial of Service (DoS) attacks and brute-force attempts on non-auth routes.
**Fix:**
- Uncomment and configure `globalLimiter`.
- Apply strict limiters to OTP and Login routes.
**Why:** Protects infrastructure and prevents resource abuse.

---

## 3. Production Hardening Checklist

| Task | Rationale |
| :--- | :--- |
| **Input Validation (Zod)** | Replaces unsafe destructuring of `req.body` with structured schema validation. |
| **Secure Error Headers** | Ensure `helmet` is fully configured to hide backend technology stacks. |
| **Environment Variable Audit** | Ensure `JWT_SECRET` and `BKASH_ID` are never hardcoded and are verified on startup. |
| **Logger Optimization** | Ensure `morgan("dev")` is disabled in production in favor of `pino-http`. |
| **Database Indexing** | Verify indexes exist on `phoneNumber`, `email`, and `isDeleted` columns. |

---

> [!IMPORTANT]
> **Priority Action:** The lack of authentication on `/user/delete/:id` and `/update/:id` is a high-risk vulnerability. Secure these routes immediately before deploying to a public environment.

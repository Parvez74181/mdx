# 🛡️ Infinity Exams — Security & Performance Audit Report

> **Date:** 14 April 2026  
> **Scope:** Full client-side React Native (Expo) application  
> **Severity Levels:** 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low

---

## Table of Contents

1. [🔴 CRITICAL — Secrets Committed to Git](#1--critical--secrets-committed-to-git)
2. [🔴 CRITICAL — Firebase Admin SDK Private Key in Repository](#2--critical--firebase-admin-sdk-private-key-in-repository)
3. [🔴 CRITICAL — WebView Debugging Enabled in Production](#3--critical--webview-debugging-enabled-in-production)
4. [🔴 CRITICAL — WebView `originWhitelist={["*"]}` Allows Arbitrary Navigation](#4--critical--webview-originwhitelist-allows-arbitrary-navigation)
5. [🟠 HIGH — No Auth Token on Protected API Calls](#5--high--no-auth-token-on-protected-api-calls)
6. [🟠 HIGH — User ID Passed in URL Query Param (Institute WebView)](#6--high--user-id-passed-in-url-query-param-institute-webview)
7. [🟠 HIGH — Password Change Endpoint Has No Auth Guard on Client](#7--high--password-change-endpoint-has-no-auth-guard-on-client)
8. [🟠 HIGH — Search Query Not Encoded (Injection Risk)](#8--high--search-query-not-encoded-injection-risk)
9. [🟠 HIGH — Cleartext Traffic Enabled for Android](#9--high--cleartext-traffic-enabled-for-android)
10. [🟠 HIGH — `usesCleartextTraffic: true` in Production Build](#10--high--usescleartexttraffic-true-in-production-build)
11. [🟡 MEDIUM — Client-Side Subscription Validation is Bypassable](#11--medium--client-side-subscription-validation-is-bypassable)
12. [🟡 MEDIUM — Exam Violation Checker is Entirely Client-Side](#12--medium--exam-violation-checker-is-entirely-client-side)
13. [🟡 MEDIUM — Phone Number Validation Commented Out](#13--medium--phone-number-validation-commented-out)
14. [🟡 MEDIUM — `console.log` / `console.error` Left Everywhere](#14--medium--consolelog--consoleerror-left-everywhere)
15. [🟡 MEDIUM — Excessive `any` Types](#15--medium--excessive-any-types)
16. [🟡 MEDIUM — `.env` File Not Platform-Aware for Production](#16--medium--env-file-not-platform-aware-for-production)
17. [🟡 MEDIUM — `getVisitorId()` Uses `localStorage` (Crashes on Native)](#17--medium--getvisitorid-uses-localstorage-crashes-on-native)
18. [🟡 MEDIUM — `getLastPathSegment()` Uses `window.location.origin` (Crashes on Native)](#18--medium--getlastpathsegment-uses-windowlocationorigin-crashes-on-native)
19. [🟡 MEDIUM — `usePremiumExams` Creates Excessive Zustand Subscriptions](#19--medium--usepremiumexams-creates-excessive-zustand-subscriptions)
20. [🟢 LOW — Upload Function Has Hardcoded MIME Type Fallback](#20--low--upload-function-has-hardcoded-mime-type-fallback)
21. [🟢 LOW — `userStore` Loading State Bug](#21--low--userstore-loading-state-bug)
22. [🟢 LOW — `signupScreen.tsx` Has Shadowed Variable `classes`](#22--low--signupscreentsx-has-shadowed-variable-classes)
23. [🟢 LOW — Empty `useEffect` in `paymentStatus.tsx`](#23--low--empty-useeffect-in-paymentstatustsx)
24. [🟢 LOW — `credentials: "include"` Not Needed in Native Fetch](#24--low--credentials-include-not-needed-in-native-fetch)
25. [🟢 LOW — Missing Error Boundaries](#25--low--missing-error-boundaries)
26. [🟢 LOW — `nanoid` Dependency for Visitor ID is Overkill](#26--low--nanoid-dependency-for-visitor-id-is-overkill)
27. [Performance Improvements Summary](#performance-improvements-summary)

---

## 1. 🔴 CRITICAL — Secrets Committed to Git

### Files Affected
- `google-services.json` (contains Firebase API key: `AIzaSyBQaPy2qXsHnfCZUT5ZFwBr0jCYm9tZq7M`)
- `infinity-exams-54fec-firebase-adminsdk-fbsvc-4d7a76d34f.json` (contains **full Firebase Admin SDK private key**)
- `.env` (contains API URL with local IP `192.168.0.101`)

### What's Wrong
These files contain **real credentials** and are tracked in Git. Anyone with access to the repository (or a leaked copy) can:
- Use the Firebase Admin SDK key to impersonate the app, access Firestore, send notifications, or even delete data.
- Use the Google Services API key for unauthorized Firebase interactions.

### Why Fix
A leaked private key means **full admin access** to your Firebase project. This is the single most dangerous issue in the codebase.

### What to Do

1. **Immediately rotate the Firebase Admin SDK key:**
   - Go to [Google Cloud Console → IAM & Admin → Service Accounts](https://console.cloud.google.com/)
   - Find `firebase-adminsdk-fbsvc@infinity-exams-54fec.iam.gserviceaccount.com`
   - Delete the existing key `4d7a76d34f...` and create a new one
   - The old key is now considered **compromised**

2. **Remove the secrets from Git history:**
   ```bash
   # Use BFG Repo Cleaner or git filter-branch to purge:
   bfg --delete-files infinity-exams-54fec-firebase-adminsdk-fbsvc-4d7a76d34f.json
   git reflog expire --expire=now --all && git gc --prune=now --aggressive
   git push --force
   ```

3. **Add to `.gitignore`:**
   ```gitignore
   # Firebase Admin SDK (NEVER commit)
   *-firebase-adminsdk-*.json
   
   # Environment files
   .env
   .env.*
   !.env.example
   
   # google-services.json is typically OK for client apps,
   # but keep the admin key files OUT.
   ```

4. **Create a `.env.example`** with placeholder values:
   ```env
   EXPO_PUBLIC_API_V1='https://your-production-api.com/api/v1'
   EXPO_PUBLIC_APP_UI_URL='https://your-production-web-app.com'
   ```

---

## 2. 🔴 CRITICAL — Firebase Admin SDK Private Key in Repository

### File Affected
- `infinity-exams-54fec-firebase-adminsdk-fbsvc-4d7a76d34f.json`

### What's Wrong
This file contains the **full private key** for the Firebase Admin SDK service account. This file should **never exist on a mobile client**. The Firebase Admin SDK is meant for backend/server use only.

### Why Fix
- This key grants **unrestricted admin access** to your entire Firebase project
- It shouldn't even be present in a client-side mobile app at all
- If this was placed here accidentally (e.g., for testing push notifications), it must be moved to the backend

### What to Do

1. **Delete the file from the project entirely:**
   ```bash
   rm infinity-exams-54fec-firebase-adminsdk-fbsvc-4d7a76d34f.json
   ```

2. **Move it to your backend server** (if needed for server-side push notification sending)

3. **Never load admin credentials on a client device** — use the client SDK (`google-services.json` / `GoogleService-Info.plist`) instead

---

## 3. 🔴 CRITICAL — WebView Debugging Enabled in Production

### Files Affected
- `app/payment/Payment.tsx` (line 136)
- `app/payment/paymentStatus.tsx` (line 109)
- `app/institute/Institute.tsx` (line 204)

### What's Wrong
```tsx
webviewDebuggingEnabled   // ← set to true / present
```
When `webviewDebuggingEnabled` is true, anyone with a USB-connected computer can use Chrome DevTools to:
- **Inspect all WebView traffic** (including bKash payment URLs and tokens)
- **Modify JavaScript** inside the WebView
- **Steal payment session data**

### Why Fix
This is especially dangerous in the **Payment.tsx** file because it exposes the bKash payment flow to tampering.

### What to Do

1. **Conditionally enable only in development:**
   ```tsx
   webviewDebuggingEnabled={__DEV__}
   ```

2. Apply this change in **all three files** mentioned above.

---

## 4. 🔴 CRITICAL — WebView `originWhitelist={["*"]}` Allows Arbitrary Navigation

### Files Affected
- `app/payment/Payment.tsx` (line 133)
- `app/payment/paymentStatus.tsx` (line 106)
- `app/institute/Institute.tsx` (line 201)

### What's Wrong
```tsx
originWhitelist={["*"]}
```
This allows the WebView to navigate to **any URL scheme**, including `javascript:`, `data:`, or `file:` URIs. Combined with the debugging flag, this is a significant attack vector.

### Why Fix
A malicious redirect from the payment gateway or injected content could navigate the WebView to a phishing URL.

### What to Do

1. **Restrict to only HTTPS and your own domains:**
   ```tsx
   originWhitelist={["https://*"]}
   ```

2. For the payment WebView specifically, consider further restricting:
   ```tsx
   originWhitelist={["https://*.bkash.com", "https://your-api-domain.com"]}
   ```

---

## 5. 🟠 HIGH — No Auth Token on Protected API Calls

### Files Affected
- `services/location.service.ts` — `registerUserLocation()` (no `Authorization` header)
- `services/notification.service.ts` — `registerPushToken()` (no `Authorization` header)
- `app/account/personalInformation.tsx` — `handleSubmit()` → `/user/update-user-profile/` (no `Authorization` header)
- `app/account/changePassword.tsx` — `handleChangePassword()` → `/user/update-password` (no `Authorization` header)
- `app/auth/signupScreen.tsx` — `getClasses()` (no auth, but may be acceptable)

### What's Wrong
Sensitive endpoints that modify user data (location, push tokens, password, profile) are called **without the Bearer token**. These requests rely only on `credentials: "include"` which sends cookies — but **React Native's `fetch` does not support cookies in the same way as browsers**.

### Why Fix
If your backend relies on the `Authorization: Bearer <token>` header (which it does for `getSession()` and `logout()`), then these endpoints are either:
- **Unprotected** (anyone can call them with just a userId), or
- **Silently failing** auth checks that the client-side doesn't notice

### What to Do

1. **Create a centralized authenticated fetch utility:**
   ```typescript
   // lib/authFetch.ts
   import { getToken } from "./saveToken";
   
   export async function authFetch(url: string, options: RequestInit = {}) {
     const token = await getToken();
     return fetch(url, {
       ...options,
       headers: {
         "Content-Type": "application/json",
         ...(token ? { Authorization: `Bearer ${token}` } : {}),
         ...options.headers,
       },
     });
   }
   ```

2. **Replace all `fetch()` calls for authenticated endpoints** with `authFetch()`.

3. **Do the same for axios calls** — create an axios instance with an interceptor:
   ```typescript
   // lib/axiosInstance.ts
   import axios from "axios";
   import { getToken } from "./saveToken";
   
   const api = axios.create({ baseURL: process.env.EXPO_PUBLIC_API_V1 });
   
   api.interceptors.request.use(async (config) => {
     const token = await getToken();
     if (token) config.headers.Authorization = `Bearer ${token}`;
     return config;
   });
   
   export default api;
   ```

---

## 6. 🟠 HIGH — User ID Passed in URL Query Param (Institute WebView)

### File Affected
- `app/institute/Institute.tsx` (line 86)

### What's Wrong
```tsx
const uri = `${process.env.EXPO_PUBLIC_APP_UI_URL}/appInterfaceUI/student/institute/${IIN}?userIdFromApp=${userId}&IINFromApp=${IIN}`;
```
The userId is passed as a **plain query parameter** in the URL. This means:
- It appears in server logs
- It's visible in the WebView's address bar
- It can be intercepted or modified

### Why Fix
User IDs should be passed through secure channels, not URL query strings.

### What to Do

1. **Pass the auth token instead** and let the web app validate the session server-side
2. If you must pass the userId, use `postMessage` bridge after the WebView loads, not URL params:
   ```tsx
   onLoadEnd={() => {
     webviewRef.current?.postMessage(JSON.stringify({
       type: "AUTH_INIT",
       userId,
       token: await getToken(),
     }));
   }}
   ```

---

## 7. 🟠 HIGH — Password Change Endpoint Has No Auth Guard on Client

### Files Affected
- `app/account/changePassword.tsx` (line 33-44)
- `app/auth/forgetPasswordScreen.tsx` (line 142)

### What's Wrong
The `/user/update-password` endpoint is called with just `phone` + `password` — **no auth token**. If the backend doesn't independently verify the session, anyone who knows a phone number can change another user's password.

### Why Fix
Password changes are one of the most sensitive operations. They need robust authentication.

### What to Do

1. **For the "Change Password" flow** (`changePassword.tsx`):
   - Send the **current password** along with the new one
   - Include the `Authorization: Bearer <token>` header
   ```typescript
   const res = await authFetch(`${BASE_URL}/user/update-password`, {
     method: "PUT",
     body: JSON.stringify({
       currentPassword: currentPassword,  // ADD THIS
       password,
       confirmPassword,
     }),
   });
   ```

2. **For the "Forgot Password" flow** (`forgetPasswordScreen.tsx`):
   - The server must verify that the OTP was validated **in the same session** before allowing the password reset
   - Consider using a **one-time reset token** returned after OTP verification, not just the phone number

---

## 8. 🟠 HIGH — Search Query Not Encoded (Injection Risk)

### File Affected
- `actions/action.ts` (line 145)

### What's Wrong
```typescript
const res = await fetch(
  `${process.env.EXPO_PUBLIC_API_V1}/home/get-search-result?query=${query}`
);
```
The `query` string is **directly interpolated** into the URL without encoding. If the query contains special characters like `&`, `#`, `=`, or spaces, it will:
- Break the URL structure
- Potentially inject additional query parameters

### Why Fix
This is an injection vector. While less dangerous than SQL injection, it can lead to SSRF-like behavior or unexpected API results.

### What to Do

```typescript
const res = await fetch(
  `${process.env.EXPO_PUBLIC_API_V1}/home/get-search-result?query=${encodeURIComponent(query)}`
);
```

---

## 9. 🟠 HIGH — Cleartext Traffic Enabled for Android

### File Affected
- `app.config.ts` (line 170)

### What's Wrong
```typescript
"expo-build-properties",
{
  android: {
    usesCleartextTraffic: true,
  },
},
```
This allows the app to make **HTTP (unencrypted)** requests on Android. Combined with the `.env` pointing to `http://192.168.0.101:5000`, this means all API traffic (including auth tokens, passwords, etc.) can be intercepted by anyone on the same network.

### Why Fix
In production, all traffic **must** be HTTPS. Cleartext is acceptable only during local development.

### What to Do

1. **Use environment-specific configs:**
   ```typescript
   android: {
     usesCleartextTraffic: process.env.NODE_ENV !== 'production',
   },
   ```

2. **Change `.env` for production to use HTTPS:**
   ```env
   EXPO_PUBLIC_API_V1='https://api.infinityexams.com/api/v1'
   EXPO_PUBLIC_APP_UI_URL='https://infinityexams.com'
   ```

3. **Use separate `.env.production` and `.env.development` files**

---

## 10. 🟠 HIGH — `usesCleartextTraffic: true` in Production Build

_This is the same issue as #9 but from a build configuration perspective._

### File Affected
- `app.config.ts` (line 169-172)

### Additional Context
The `expo-build-properties` plugin is listed **twice** in the plugins array (lines 166 and 188). The second occurrence may override the first. This is a configuration bug.

### What to Do

1. **Remove the duplicate** `expo-build-properties` plugin entry (line 188)
2. **Set `usesCleartextTraffic: false`** for production builds
3. Use EAS Build profiles to differentiate dev vs. production:
   ```json
   // eas.json
   {
     "build": {
       "development": { "env": { "EXPO_PUBLIC_API_V1": "http://..." } },
       "production": { "env": { "EXPO_PUBLIC_API_V1": "https://..." } }
     }
   }
   ```

---

## 11. 🟡 MEDIUM — Client-Side Subscription Validation is Bypassable

### File Affected
- `utils/index.ts` → `checkStudentSubscriptionActiveStatus()` (line 240-262)

### What's Wrong
Subscription validity is checked entirely on the client by comparing dates:
```typescript
return today <= expiryDate;
```
A user could modify the device clock or patch the app bundle to bypass this check.

### Why Fix
Premium features should be gated on the **server side**. The client check is fine for UX purposes (showing/hiding UI), but the backend must always validate subscription status before serving premium content.

### What to Do

1. **Ensure backend validates subscription** before returning premium exam data
2. Keep the client check for UI only (showing "Upgrade" buttons, etc.)
3. Mark this function clearly:
   ```typescript
   /**
    * UI-only check. The server MUST independently validate subscription.
    */
   export const checkStudentSubscriptionActiveStatus = ...
   ```

---

## 12. 🟡 MEDIUM — Exam Violation Checker is Entirely Client-Side

### File Affected
- `components/ExamViolationChecker.tsx`

### What's Wrong
The anti-cheating mechanism:
- Counts violations in a `useRef` (resets when component unmounts)
- Auto-cancels exam with `router.replace("/(tabs)/home")` after 3 violations
- **Never reports violations to the server**

### Why Fix
A student can:
- Kill and restart the app to reset the violation counter
- Modify the app to disable this component entirely
- Switch apps freely without any server-side record

### What to Do

1. **Report each violation to the server** via API call
2. **Let the server decide when to cancel** the exam
3. **Store violation count server-side** so app restarts don't reset it
4. Example:
   ```typescript
   const reportViolation = async () => {
     if (!canReport()) return;
     violationCount.current++;
     
     // Report to server
     await authFetch(`${BASE_URL}/exam/report-violation`, {
       method: "POST",
       body: JSON.stringify({
         examId: currentExamId,
         violationType: "app_background",
         count: violationCount.current,
       }),
     });
     
     // Server response determines if exam should be cancelled
   };
   ```

---

## 13. 🟡 MEDIUM — Phone Number Validation Commented Out

### Files Affected
- `app/auth/otpScreen.tsx` (lines 31-35)
- `app/auth/forgetPasswordScreen.tsx` (lines 66-70)

### What's Wrong
```typescript
// else if (!/^(?:\+88|01)?\d{11}$/.test(phone)) {
//   showToast("Info", "warning", "Please provide a valid phone number");
//   ...
// }
```
Phone number validation regex is **commented out**. This means:
- Invalid phone numbers are sent to the server
- Extra OTP SMS costs for invalid numbers
- Potential abuse by flooding the OTP endpoint

### Why Fix
Client-side validation is the first line of defense. It prevents unnecessary API calls and improves UX.

### What to Do

1. **Uncomment and fix the validation:**
   ```typescript
   const isValidBDPhone = (phone: string) => /^01[3-9]\d{8}$/.test(phone);
   
   if (!isValidBDPhone(phoneNumber)) {
     showToast({ title: "Error", color: "danger", description: "Please provide a valid Bangladesh phone number" });
     setLoading(false);
     return;
   }
   ```

2. **Create a shared validation utility** in `utils/index.ts` to avoid duplication:
   ```typescript
   export const isValidBDPhone = (phone: string) => /^01[3-9]\d{8}$/.test(phone);
   ```

---

## 14. 🟡 MEDIUM — `console.log` / `console.error` Left Everywhere

### Files Affected
Almost every file — `action.ts`, `loginScreen.tsx`, `signupScreen.tsx`, `otpScreen.tsx`, `forgetPasswordScreen.tsx`, `Payment.tsx`, `Institute.tsx`, `location.service.ts`, `notification.service.ts`, `useLocation.ts`, `useNotifications.ts`, etc.

### What's Wrong
```typescript
console.log(error);
console.error("Failed to fetch session:", error);
console.log("⚠️ App backgrounded");
console.log("Link clicked:", pathname, href);
```

### Why Fix
- **Performance:** Excessive logging slows down the JS thread, especially on low-end devices
- **Security:** Error messages and URLs visible in logcat/device console may contain sensitive data (tokens, user IDs, etc.)
- **Bundle size:** String literals for log messages add to the bundle

### What to Do

1. **Install a proper logger** that respects build mode:
   ```typescript
   // lib/logger.ts
   const logger = {
     log: (...args: any[]) => { if (__DEV__) console.log(...args); },
     error: (...args: any[]) => { if (__DEV__) console.error(...args); },
     warn: (...args: any[]) => { if (__DEV__) console.warn(...args); },
   };
   export default logger;
   ```

2. **Replace all `console.*` calls** with `logger.*`

3. **Consider a Babel plugin** to strip console calls in production:
   ```javascript
   // babel.config.js
   module.exports = function (api) {
     api.cache(true);
     const plugins = [];
     if (process.env.NODE_ENV === 'production') {
       plugins.push(['transform-remove-console', { exclude: ['error'] }]);
     }
     return { presets: ['babel-preset-expo'], plugins };
   };
   ```

---

## 15. 🟡 MEDIUM — Excessive `any` Types

### Files Affected
- `store/premiumExamsData.ts` — `selectedSubject: any`, `selectedTopicsData: any`
- `store/themeStore.ts` — `theme: any`
- `store/userStore.ts` — `setUser: (user: any) => void`
- `actions/action.ts` — `login(data: any)`, `logout(id: any)`
- `lib/toast.tsx` — `iconMap: any`
- `components/ExamViolationChecker.tsx`, `MathRenderer.tsx`, etc.

### What's Wrong
Using `any` disables TypeScript's type checking, leading to:
- Runtime crashes that could have been caught at compile time
- No IntelliSense/autocomplete
- Hard-to-debug issues in production

### Why Fix
TypeScript is only useful if types are actually enforced. `any` makes it equivalent to JavaScript with extra steps.

### What to Do

1. **Define proper interfaces** for all data structures:
   ```typescript
   // types/exam.ts
   interface Subject {
     id: string;
     name: string;
     classId: string;
   }
   
   interface TopicData {
     chapterId: string;
     topicId: string;
     name: string;
   }
   ```

2. **Replace `any` with proper types** across all stores and actions
3. **Enable `"strict": true`** in `tsconfig.json` and fix all resulting errors
4. Start with the most critical files: `userStore.ts`, `action.ts`, `premiumExamsData.ts`

---

## 16. 🟡 MEDIUM — `.env` File Not Platform-Aware for Production

### File Affected
- `.env`

### What's Wrong
```env
EXPO_PUBLIC_API_V1='http://192.168.0.101:5000/api/v1'
EXPO_PUBLIC_APP_UI_URL='http://192.168.0.101:3000'
```
The production `.env` points to a **local development IP** over **HTTP**. If this is accidentally used in a production build:
- The app won't work outside your local network
- All traffic is unencrypted

### Why Fix
Production builds should never reference localhost or private IPs.

### What to Do

1. **Use EAS environment variables** for production builds in `eas.json`:
   ```json
   {
     "build": {
       "production": {
         "env": {
           "EXPO_PUBLIC_API_V1": "https://api.infinityexams.com/api/v1",
           "EXPO_PUBLIC_APP_UI_URL": "https://infinityexams.com"
         }
       }
     }
   }
   ```

2. **Add `.env` to `.gitignore`** (currently only `.env*.local` is ignored)
3. **Create `.env.example`** with placeholder values for documentation

---

## 17. 🟡 MEDIUM — `getVisitorId()` Uses `localStorage` (Crashes on Native)

### File Affected
- `utils/index.ts` (line 158-165)

### What's Wrong
```typescript
export function getVisitorId() {
  let id = localStorage.getItem("visitorId");
  // ...
  localStorage.setItem("visitorId", id);
  return id;
}
```
`localStorage` does **not exist** in React Native. Calling this function will throw a `ReferenceError` and crash the app.

### Why Fix
This is a direct crash bug. Even if not currently called, it's an accident waiting to happen.

### What to Do

1. **Replace with `AsyncStorage`:**
   ```typescript
   import AsyncStorage from "@react-native-async-storage/async-storage";
   
   export async function getVisitorId() {
     let id = await AsyncStorage.getItem("visitorId");
     if (!id) {
       id = nanoid(10) + getRandomInt(10, 50);
       await AsyncStorage.setItem("visitorId", id);
     }
     return id;
   }
   ```

2. **Or delete it** if it's unused (it appears to be leftover from a web version)

---

## 18. 🟡 MEDIUM — `getLastPathSegment()` Uses `window.location.origin` (Crashes on Native)

### File Affected
- `utils/index.ts` (line 17-21)

### What's Wrong
```typescript
export function getLastPathSegment(url: string): string {
  const pathname = new URL(url, window.location.origin).pathname;
  // ...
}
```
`window` is undefined in React Native. This will crash if called.

### Why Fix
Like issue #17, this is a runtime crash bug from web code that was ported without adaptation.

### What to Do

1. **Remove the `window.location.origin` dependency:**
   ```typescript
   export function getLastPathSegment(url: string): string {
     // Handle both full URLs and relative paths
     try {
       const pathname = new URL(url).pathname;
       const segments = pathname.replace(/\/+$/, "").split("/");
       return decodeURIComponent(segments[segments.length - 1]);
     } catch {
       // Fallback for relative paths
       const segments = url.replace(/\/+$/, "").split("/");
       return decodeURIComponent(segments[segments.length - 1]);
     }
   }
   ```

---

## 19. 🟡 MEDIUM — `usePremiumExams` Creates Excessive Zustand Subscriptions

### File Affected
- `store/usePremiumExams.ts`

### What's Wrong
```typescript
export const usePremiumExams = () => {
  const selectedSubject = premiumExamsData((s) => s.selectedSubject ?? null);
  const setSelectedSubject = premiumExamsData((s) => s.setSelectedSubject);
  // ... 15+ separate selectors
};
```
Each `premiumExamsData((s) => ...)` call creates a **separate Zustand subscription**. This hook creates **~17 subscriptions** every time a component using it renders. Any state change in the store will trigger 17 equality checks.

### Why Fix
This causes unnecessary re-renders and performance degradation, especially on the exam configuration screen.

### What to Do

1. **Use a single selector with `useShallow`:**
   ```typescript
   import { useShallow } from "zustand/react/shallow";
   
   export const usePremiumExams = () => {
     return premiumExamsData(
       useShallow((s) => ({
         selectedSubject: s.selectedSubject ?? null,
         setSelectedSubject: s.setSelectedSubject,
         selectedTopicsData: s.selectedTopicsData ?? [],
         setSelectedTopicsData: s.setSelectedTopicsData,
         // ... rest of the selectors
       }))
     );
   };
   ```

2. **Or let components select only what they need** directly from the store, instead of using this mega-hook.

---

## 20. 🟢 LOW — Upload Function Has Hardcoded MIME Type Fallback

### File Affected
- `utils/index.ts` (line 123-126)

### What's Wrong
```typescript
if (ext === "pdf") mimeType = "application/pdf";
else mimeType = "image/webp";
```
This assumes every non-PDF file is a WebP image. If a user uploads a JPEG or PNG, the MIME type will be wrong.

### Why Fix
Incorrect MIME types may cause the server to reject the upload or process it incorrectly.

### What to Do

```typescript
const mimeMap: Record<string, string> = {
  pdf: "application/pdf",
  webp: "image/webp",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  gif: "image/gif",
};
const mimeType = mimeMap[ext || ""] ?? "application/octet-stream";
```

---

## 21. 🟢 LOW — `userStore` Loading State Bug

### File Affected
- `store/userStore.ts` (line 36)

### What's Wrong
```typescript
setUser: (user) =>
  set(() => ({
    user,
    isAuthenticated: Boolean(user?.id),
    loading: Boolean(user?.id),  // ← Bug: loading should be FALSE when user is set
  })),
```
When a user is successfully set, `loading` is set to `true` (because `Boolean(user.id)` is `true`). This means the app may show loading indicators even after authentication.

### Why Fix
This is a logic bug that may cause infinite loading states or flickering UI.

### What to Do

```typescript
setUser: (user) =>
  set(() => ({
    user,
    isAuthenticated: Boolean(user?.id),
    loading: false,  // ← Always false after setting user
  })),
```

---

## 22. 🟢 LOW — `signupScreen.tsx` Has Shadowed Variable `classes`

### File Affected
- `app/auth/signupScreen.tsx`

### What's Wrong
```typescript
const classes = [                     // ← line 33: outer const
  { id: "ssc", label: "SSC" },
  { id: "hsc", label: "HSC" },
  { id: "degree", label: "Degree" },
];

export default function SignUpScreen() {
  const [classes, setClasses] = useState<Classes[]>([]);  // ← line 53: shadows outer
  // ...
}
```
The state variable `classes` shadows the top-level constant with the same name. The top-level constant is never used because the state variable takes precedence.

### Why Fix
This is dead code that confuses developers and may cause subtle bugs if the intent was to use the static constant as initial state.

### What to Do

1. **Remove the unused top-level `classes` constant** (lines 33-37), or
2. **Use it as the initial state:**
   ```typescript
   const initialClasses = [
     { id: "ssc", label: "SSC" },
     { id: "hsc", label: "HSC" },
     { id: "degree", label: "Degree" },
   ];
   
   const [classes, setClasses] = useState<Classes[]>(initialClasses);
   ```

---

## 23. 🟢 LOW — Empty `useEffect` in `paymentStatus.tsx`

### File Affected
- `app/payment/paymentStatus.tsx` (lines 40-43)

### What's Wrong
```typescript
useEffect(() => {
  if (paymentMetaData) {
  }
}, [params, paymentMetaData]);
```
This `useEffect` does nothing. It's either leftover from a previous implementation or unfinished code.

### Why Fix
Dead code creates confusion and is a minor performance overhead.

### What to Do

**Remove the empty `useEffect` entirely.**

---

## 24. 🟢 LOW — `credentials: "include"` Not Needed in Native Fetch

### Files Affected
- `app/auth/signupScreen.tsx` (line 122)
- `app/auth/otpScreen.tsx` (line 42)
- `app/auth/forgetPasswordScreen.tsx` (line 77, 121)
- `app/account/changePassword.tsx` (line 39)
- `app/account/personalInformation.tsx` (line 83)
- `app/auth/affiliateLinkScreen.tsx` (line 38)
- `utils/index.ts` (line 145, `uploadFile`)

### What's Wrong
```typescript
credentials: "include",
```
`credentials: "include"` tells the browser to send cookies with cross-origin requests. In **React Native**, there are no cookies — authentication is handled via the `Authorization` header (which you store in SecureStore).

### Why Fix
This does nothing helpful in React Native and gives a false sense of security. Developers might think cookies are being sent for authentication when they're not.

### What to Do

1. **Remove `credentials: "include"` from all native fetch calls**
2. **Add the `Authorization` header instead** (see issue #5)

---

## 25. 🟢 LOW — Missing Error Boundaries

### What's Wrong
The app has no React Error Boundaries. If any component throws a rendering error, the **entire app crashes** with a white screen or a generic error.

### Why Fix
Error Boundaries gracefully catch rendering errors and show a fallback UI instead of crashing the entire app.

### What to Do

1. **Create a global Error Boundary component:**
   ```typescript
   // components/ErrorBoundary.tsx
   import React from "react";
   import { View, Text, TouchableOpacity } from "react-native";
   
   interface State { hasError: boolean; error?: Error; }
   
   class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
     state: State = { hasError: false };
   
     static getDerivedStateFromError(error: Error) {
       return { hasError: true, error };
     }
   
     handleReset = () => {
       this.setState({ hasError: false, error: undefined });
     };
   
     render() {
       if (this.state.hasError) {
         return (
           <View style={{ flex: 1, justifyContent: "center", alignItems: "center", padding: 20 }}>
             <Text style={{ fontSize: 18, fontWeight: "bold", marginBottom: 10 }}>
               কিছু ভুল হয়ে গেছে
             </Text>
             <TouchableOpacity onPress={this.handleReset}>
               <Text style={{ color: "blue" }}>আবার চেষ্টা করুন</Text>
             </TouchableOpacity>
           </View>
         );
       }
       return this.props.children;
     }
   }
   
   export default ErrorBoundary;
   ```

2. **Wrap the app in `_layout.tsx`:**
   ```tsx
   <ErrorBoundary>
     <QueryProvider>
       <Stack ... />
     </QueryProvider>
   </ErrorBoundary>
   ```

---

## 26. 🟢 LOW — `nanoid` Dependency for Visitor ID is Overkill

### File Affected
- `utils/index.ts` (line 2, line 161)

### What's Wrong
`nanoid` is imported but only used in one place (`getVisitorId()`) which itself may crash due to `localStorage` (issue #17). It adds ~1KB to the bundle.

### Why Fix
Unnecessary dependencies increase bundle size and potential attack surface.

### What to Do

1. If `getVisitorId()` is kept, use a simpler approach:
   ```typescript
   import * as Crypto from "expo-crypto";
   
   export async function getVisitorId() {
     const id = await AsyncStorage.getItem("visitorId");
     if (id) return id;
     const newId = Crypto.randomUUID();
     await AsyncStorage.setItem("visitorId", newId);
     return newId;
   }
   ```

2. If `getVisitorId()` is removed entirely, **also remove the `nanoid` import** and uninstall it.

---

## Performance Improvements Summary

| # | Issue | Impact | Effort |
|---|-------|--------|--------|
| P1 | `usePremiumExams` creates 17+ Zustand subscriptions per render | High — causes extra re-renders | Low — use `useShallow` |
| P2 | `console.log` everywhere | Medium — pollutes JS thread | Low — use logger wrapper |
| P3 | WebView `cacheEnabled={false}` in Institute screen | Medium — every visit re-downloads all assets | Low — set `cacheEnabled={true}` |
| P4 | No image caching strategy | Medium — images re-download on every render | Medium — use `expo-image`'s caching (you already have it installed, make sure all `<Image>` uses `expo-image`) |
| P5 | Tab screens import large components eagerly | Medium — slow initial load | Medium — use `React.lazy()` with Suspense |
| P6 | `SwiperFlatList` on landing screen loads all images eagerly | Low — both images loaded at startup | Low — already only 2 images, acceptable |
| P7 | Duplicate `expo-build-properties` plugin in `app.config.ts` | Low — may cause config conflicts | Low — remove duplicate |
| P8 | `MathRenderer.tsx` creates new `StyleSheet` inside component on each import | N/A — `StyleSheet.create` is outside render, this is fine | N/A |

---

## 🎯 Priority Action Plan

### Immediate (Before Next Release)
1. ✅ **Rotate Firebase Admin SDK key** and **remove it from repo** (#1, #2)
2. ✅ **Add `.env` and admin key files to `.gitignore`** (#1)
3. ✅ **Set `webviewDebuggingEnabled={__DEV__}`** in all WebViews (#3)
4. ✅ **Restrict `originWhitelist`** in all WebViews (#4)
5. ✅ **Fix `usesCleartextTraffic`** and remove duplicate plugin (#9, #10)

### Short-Term (Within 1-2 Sprints)
6. 🔨 **Create `authFetch()` utility** and add auth headers to all protected endpoints (#5)
7. 🔨 **URL-encode search queries** (#8)
8. 🔨 **Uncomment phone validation** (#13)
9. 🔨 **Fix `userStore.loading` bug** (#21)
10. 🔨 **Replace `console.*` with a production-safe logger** (#14)

### Medium-Term (Within 1 Month)
11. 📋 **Add server-side violation reporting** for exams (#12)
12. 📋 **Fix web-only APIs** (`localStorage`, `window.location`) (#17, #18)
13. 📋 **Optimize Zustand subscriptions** in `usePremiumExams` (#19)
14. 📋 **Add Error Boundaries** (#25)
15. 📋 **Type-safety improvements** — replace `any` with proper types (#15)

### Ongoing
16. 🔄 **Remove dead code** (shadowed variables, empty hooks, unused imports) (#22, #23, #26)
17. 🔄 **Remove `credentials: "include"`** from native fetch calls (#24)
18. 🔄 **Production env setup** — `.env.production` with HTTPS URLs (#16)

---

> **Note:** This audit covers the client-side codebase only. A separate audit of the **backend API** is strongly recommended to verify that:
> - All endpoints properly validate auth tokens
> - OTP verification is session-bound and rate-limited
> - Subscription checks are enforced server-side
> - Input validation and sanitization are handled before DB queries

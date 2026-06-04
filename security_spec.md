# Firebase Security Specification

## Data Invariants
1. `reciters`: Grid of all Quran reciters. Read is public. Write (Create, Update, Delete) is restricted strictly to verified Administrators listed in the `admins` collection.
2. `reciters/{reciterId}/surahs`: The surahs and audio links for each reciter. Read is public. Write (Create, Update, Delete) is restricted strictly to verified Administrators.
3. `users/{userId}/favorites`: Saved favorite reciters and surahs. Read and Write (Create, Update, Delete) are restricted strictly to the matching authenticated user owner (`userId == request.auth.uid`). No member of the public can read or write another user's favorites.
4. `admins`: Admin registry mapping UID to email. Read is authenticated. Write is restricted.

---

## The "Dirty Dozen" Malicious Payloads

### 1. The ID Poisoning Attack (Reciters)
* **Goal**: Inject huge, junk string IDs into the `reciters` collection to crash queries or create invalid indices.
* **Payload**: `db.collection('reciters').doc('a_reciter_' + 'x'.repeat(1000)).set({ name: 'القارئ', photoUrl: 'https://...', bio: 'سيرة ذاتية', surahCount: 1 })`
* **Expected Result**: `PERMISSION_DENIED` (ID size > 128 or invalid characters).

### 2. The Identity Spoofing Attack (Favorites)
* **Goal**: Save favorites on behalf of another user ID.
* **Payload**: Authenticated as `user_abc`. Attempting write to `users/user_xyz/favorites/fav_123` with payload: `{ type: 'reciter', reciterId: 'reciter_123', name: 'Al-Ghamdi', createdAt: request.time }`.
* **Expected Result**: `PERMISSION_DENIED` (UID mismatch: `user_abc` != `user_xyz`).

### 3. The Admin Spoofing Attack (Reciters Creation)
* **Goal**: A regular non-admin user attempts to create a new reciter.
* **Payload**: Authenticated as `user_abc` (not in `admins`). Set document in `reciters/new_reciter`: `{ name: 'القارئ الجديد', photoUrl: 'https://...', bio: 'سيرة ذاتية جديدة', surahCount: 0 }`.
* **Expected Result**: `PERMISSION_DENIED` (User is not an admin).

### 4. Shadow Field Injection (Reciter Update)
* **Goal**: Update a reciter but inject undocumented or security fields like `isApproved: true` or `isAdmin: true` to bypass client state checks.
* **Payload**: Authenticated as Admin `user_admin`. Attempt update with: `{ name: 'القارئ المحدث', photoUrl: 'https://...', bio: 'سيرة ذاتية جديدة', surahCount: 5, databaseRootUser: true }`.
* **Expected Result**: `PERMISSION_DENIED` (Affected keys do not match valid schema, strict field checking).

### 5. Temporal Fraud (Timestamp Manipulation)
* **Goal**: Update reciter with a fake, future `updatedAt` value.
* **Payload**: Authenticated as Admin `user_admin`. Send: `{ name: 'القارئ المحدث', photoUrl: 'https://...', bio: 'سيرة ذاتية جديدة', surahCount: 10, updatedAt: '2030-01-01T00:00:00Z' }`.
* **Expected Result**: `PERMISSION_DENIED` (Must use server timestamp `request.time`).

### 6. Value Poisoning (Surah Number Out of Bounds)
* **Goal**: Insert a surah with number 999 (which is invalid, Quran has 114 surahs).
* **Payload**: Authenticated as Admin. Write to `reciters/reciter_1/surahs/surah_999`: `{ number: 999, name: 'سورة وهمية', audioUrl: 'https://...', duration: 120 }`.
* **Expected Result**: `PERMISSION_DENIED` (Value bounds check failed).

### 7. Unauthenticated User Savior (Write Favorites)
* **Goal**: Write a favorite item without signing in.
* **Payload**: Unauthenticated user attempts to write to `users/anonymous_user/favorites/fav_1`: `{ type: 'reciter', reciterId: 'reciter_1', name: 'Al-Ghamdi' }`.
* **Expected Result**: `PERMISSION_DENIED` (`request.auth != null` fails).

### 8. Denial of Wallet Query Scraping (Blanket Reads)
* **Goal**: Malicious scraper attempts to download all users' private favorites with a wildcard list.
* **Payload**: Authenticated as `user_abc`. Attempting `getDocs(collectionGroup('favorites'))` without limits or user filtering.
* **Expected Result**: `PERMISSION_DENIED` (List operations protected and verified against authenticated resource owners).

### 9. Mutating Immortal Fields (Favorites Type Mutation)
* **Goal**: Change the `type` or `reciterId` of a favorite item after creation (e.g., from 'reciter' to 'surah', which would confuse UI state).
* **Payload**: Authenticated as owner. Update favorite: `{ type: 'surah' }`.
* **Expected Result**: `PERMISSION_DENIED` (`type` field is marked immutable).

### 10. Spam Resource Exhaustion (Extremely Long Biography)
* **Goal**: Inject a 5MB string into the biography field of a reciter.
* **Payload**: Authenticated as Admin. Write to reciter bio with a 2,000,000-character string.
* **Expected Result**: `PERMISSION_DENIED` (String length exceeded limit).

### 11. Audio URL Spoofing (Malicious Protocol)
* **Goal**: Create a surah recording with an invalid audio URL (e.g. `javascript:alert(1)` or empty).
* **Payload**: Authenticated as Admin. Write: `{ number: 1, name: 'الفاتحة', audioUrl: 'javascript:alert(1)', duration: 100 }`.
* **Expected Result**: `PERMISSION_DENIED` (Format check failed).

### 12. Orphaned Surah Insertion
* **Goal**: Create a surah inside a non-existent or deleted reciter document.
* **Payload**: Write to `reciters/deleted_reciter_id/surahs/surah_1` with valid surah details.
* **Expected Result**: `PERMISSION_DENIED` (Parent document validation exists via `exists()`).

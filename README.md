# Kiskis Client

**Keep It Safe. Keep It Secret.**

Kiskis delivers API keys and configuration to your app at runtime — secured by hardware attestation. No keys in your binary. No Firebase. No vendor lock-in.

| Platform | Status | Directory |
|----------|--------|-----------|
| **iOS** | Available | [ios/](ios/) |
| **Android** | Coming soon | [android/](android/) |
| **Web** | Coming soon | [web/](web/) |

---

## iOS Quick Start

### Installation

In Xcode: **File → Add Package Dependencies** → enter:

```
https://github.com/kiskisdev/client
```

Select subdirectory **`ios`**, then add the **Kiskis** library.

**CLI tool** (for uploading configs from your terminal):
```bash
brew tap kiskisdev/homebrew-cli
brew install kiskis
```

**Requirements:** iOS 14+, Swift 5.9+, Xcode 15+

**Xcode capabilities needed:**
- App Attest
- Push Notifications
- Background Modes → Remote notifications

### Usage

```swift
import Kiskis

// Only Team ID is required — Bundle ID and version are auto-detected
let kiskis = KiskisClient(teamId: "A1B2C3D4E5")
let config = try await kiskis.fetchConfig()
let stripeKey = config.string("api_keys.stripe")
```

That single call:
1. Registers the device via Apple App Attest (first launch only, 1-2 sec)
2. Signs every request with the Secure Enclave (no tokens, no passwords)
3. Fetches version-matched config from the Kiskis server
4. Caches in encrypted local storage for offline use
5. Refreshes silently in the background

### What Gets Auto-Detected

| Parameter | Source | Can Override? |
|-----------|--------|---------------|
| Team ID | You provide it | Required |
| Bundle ID | `Bundle.main.bundleIdentifier` | Yes, pass `bundleId:` |
| App Version | `CFBundleShortVersionString` in Info.plist | No (always auto-detected) |
| Environment | `#if DEBUG` → sandbox, else production | Yes, pass `environment:` |

Together Team ID + Bundle ID + Version form the **three-part config lookup key**.

---

## How It Works

### The Problem

You have a Stripe key. Your iOS app needs it. Where do you put it?

**Option A: Hardcode it in the app.** Bad. Anyone with a Mac can download your `.ipa` from the App Store, unzip it (it's just a ZIP file), and run `strings` to find every string literal in your binary. Your Stripe key shows up in minutes.

**Option B: Download it from a server.** Better — the key isn't in the binary. But now: **how does the server know it's YOUR app asking, and not a Python script?**

You can't use a password or API key to authenticate the app, because where would you store THAT? You're right back to Option A. This is the **bootstrap problem** — you can't use a secret to get a secret.

### The Solution: Prove the Hardware, Not a Password

Apple built a tamper-proof chip into every modern iPhone called the **Secure Enclave**. This chip generates a cryptographic key pair where the private key **physically cannot leave the chip.** Not "shouldn't leave." Cannot. The key is fused into the silicon. There's no API to read it. The OS can't read it. A jailbreak can't read it.

### How Public/Private Keys Work (and Why)

You've probably used SSH keys or HTTPS. They're based on the same idea: **asymmetric cryptography** — two keys that are mathematically linked but serve opposite purposes.

```
Private Key                              Public Key
───────────                              ──────────
• Kept secret (in the Secure Enclave)    • Shared openly (sent to Kiskis)
• Can SIGN data                          • Can VERIFY signatures
• There is only one                      • Anyone can have a copy
```

The critical property: **you cannot work backwards from the public key to figure out the private key.** Even with all the computers on Earth. This is a proven mathematical property, not a software feature.

**How signing works:**

Think of the private key as a wax seal that only you have, and the public key as a guide for checking whether a seal is genuine.

```
Signing (by the Secure Enclave):
    Request data: "Give me the config for version 2.1.3"
    Private key + data ──> mathematical function ──> Signature
                                                     (unique bytes that could ONLY
                                                      come from this private key
                                                      and this exact data)

Verifying (by Kiskis server):
    Request data + Signature + Public key ──> math check ──> Valid? YES ✓
```

If the signature is valid, Kiskis knows with mathematical certainty that the request came from the same physical chip that created the key pair. Not a copy. Not a simulation. That exact chip.

---

## Step by Step: What Happens When Your App Launches

### Step 1: Key Generation (one time, first install)

```
Your App                           iPhone's Secure Enclave
────────                           ───────────────────────
"Generate a key pair"  ──────────>  Creates:
                                      Private key (STAYS IN CHIP FOREVER)
                                      Public key
                       <──────────  Returns: public key + keyId
```

### Step 2: Attestation Ceremony (one time, first install)

The app proves to Kiskis that this key pair was generated inside a REAL Secure Enclave on a REAL iPhone — not fabricated by a script.

```
Your App               Apple's Servers              Kiskis Server
────────               ───────────────              ─────────────
                                                    "Here's a random
                                                     challenge: x7Bf9..."
                       <──────────────────────────
Secure Enclave signs──> Apple verifies:
                        - Real Secure Enclave? ✓
                        - Unmodified app binary? ✓
                        - Correct Bundle ID? ✓
                        Returns signed attestation
                        (Apple's stamp of approval)

App sends attestation ──────────────────────────>   Kiskis verifies:
+ keyId + nonce                                     - Apple's signature → Root CA? ✓
                                                    - Challenge matches? ✓
                                                    - Bundle ID matches? ✓
                                                    Stores public key in database
                       <────────────────────────── { registered: true }
```

No tokens were issued. No passwords exchanged. The device proved itself through hardware.

### Attestation vs Assertion (One-Time Setup vs Every Request)

The attestation ceremony (Step 2) involves Apple's servers. It's slow (1-2 seconds). You only do it **once per device.** After that, every request uses **assertions** instead.

An assertion is a signature created by the Secure Enclave — **locally, on the device, with no network call to Apple.** Fast (<100ms). Proves the same thing: "this request came from the same hardware that attested."

```
Attestation (one-time)                     Assertion (every request)
──────────────────────                     ────────────────────────
• Registers the device with Kiskis         • Proves it's still the same device
• Round-trip to Apple's servers            • Local only — no call to Apple
• Slow (1-2 seconds)                       • Fast (<100ms)
• Happens once per install                 • Happens on every config fetch
```

There are no tokens in this system. No JWTs. No refresh flows. Every single request is individually signed by the hardware chip. Nothing to steal, nothing to expire.

### Step 3: Fetching Config (every subsequent request)

```
Your App                                           Kiskis Server
────────                                           ─────────────
Secure Enclave signs request
(local, <100ms, no network to Apple)

Sends:
  GET /config?version=2.1.3
  X-Key-Id: abc123
  X-Assertion: <signed assertion>    ────────>  1. Look up public key by keyId
  X-Client-Data: <request hash>                 2. Verify assertion signature ✓
                                                3. Check signCount > last seen ✓
                                                4. Match version: 2.1.3 → "2.*"
                                                5. Return config
                          <──────────────────── { config: {"stripe":"sk_v2"} }
```

**Why signCount matters:** Every time the Secure Enclave signs, it increments a counter. Kiskis stores the last value. If someone captures a request and replays it, the counter is stale — rejected.

---

## Why This Can't Be Faked

| Attack | What Happens |
|--------|-------------|
| **Script calls the API** | No Secure Enclave → no valid assertion → 401 |
| **Fake attestation** | Must be signed by Apple → can't forge Apple's signature → 403 |
| **Modified app** | Apple checks binary hash during attestation → refused |
| **Replay captured request** | signCount already incremented → stale → 403 |
| **Jailbreak extracts key** | Secure Enclave is a separate chip with its own processor → key physically inaccessible |

---

## Multiple Devices, New Devices, and Restores

**Same user, multiple devices:** Each device attests independently with its own Secure Enclave key. All get the same config (same Team ID + Bundle ID + version). Kiskis sees devices, not users.

**User buys a new phone:** New phone generates fresh keys, attests, works immediately. Old phone's key still works until app is deleted.

**User restores from iCloud backup:** The old `keyId` transfers in the backup but the Secure Enclave private key does NOT (it's hardware-bound). The SDK detects the failed assertion, clears the stale key, re-attests with new hardware automatically. Transparent to the user.

---

## Complete System Lifecycle

### Developer Setup (once)

```
Developer                               Kiskis                          AWS
─────────                               ──────                          ───
Signs up at kiskis.dev/dashboard
Creates Kiskis key (kk_prod_...)
Creates secrets.json on their machine
Runs: kiskis-cli upload                 Management Lambda:
  --file secrets.json                   1. Verify provisioning key
  --key kk_prod_...                     2. Sign TeamID.BundleID → S3 path
  --ver "*"                             3. Store config in S3 vault (encrypted)
```

### Every App Launch

```
Launch 1 (first install):
  Attestation with Apple (1-2 sec) → device registered
  Assertion-signed config fetch → config returned
  Cache to encrypted local storage

Launch 2+ (cache hit):
  Return cached config instantly (0ms)
  Background: assertion-signed refresh → update cache silently

Launch after 8 days offline (past maxStaleness):
  Cache expired → must fetch from server
  If network available → assertion → fresh config
  If offline → load fallback bundle (if provided)
```

### Emergency Key Rotation

```
Developer uploads new key              Kiskis updates S3 manifest
kiskis-cli upload --file new.json      Archives old version (rollback available)
                                       Sends silent push to all devices (APNs)
                                       Devices re-fetch within minutes
```

---

## What This Means for You as a Developer

You don't implement any of this yourself. The SDK handles everything:

```swift
let config = try await KiskisClient(teamId: "A1B2C3D4E5").fetchConfig()
```

Behind that one line: key generation, attestation, assertion signing, version matching, caching, background refresh, device migration detection, offline fallback.

### The Bottom Line

Traditional API security: "Here's a password. Don't let anyone see it."

Kiskis: "Prove you're a real iPhone running the real app, using a key that physically cannot leave the hardware chip. No passwords. No tokens. The silicon is the credential."

---

## Security Model

### Client Authentication (3 layers)

| Layer | Mechanism | What It Proves |
|-------|-----------|---------------|
| Hardware | App Attest assertion (Secure Enclave) | Genuine device + unmodified app |
| Replay Prevention | signCount (increments every request) | Each request is unique |
| Transport | TLS 1.3 | Encrypted in transit |

### Data Protection

| Layer | Protection |
|-------|-----------|
| **S3 vault** | SSE-KMS encryption at rest, bucket policy denies all except Lambda |
| **S3 paths** | Ed25519-signed hashes — impossible to guess or probe |
| **Kiskis keys** | Only SHA-256 hash stored — raw key shown once at creation |
| **On-device cache** | iOS sandbox + NSFileProtectionComplete + excluded from backups |
| **Zero-Knowledge** | AES-256-GCM client-side encryption — server cannot read secrets |

---

## iOS SDK Integration

### Basic Usage

```swift
// Only Team ID is required
let kiskis = KiskisClient(teamId: "A1B2C3D4E5")
let config = try await kiskis.fetchConfig()

// Access values by key path
let stripe = config.string("api_keys.stripe")
let maxMB = config.int("features.max_upload_mb")
let dark = config.bool("features.dark_mode")
let pricing = config.array("pricing")
let endpoints = config.dict("endpoints")
```

### Non-Blocking Init (Recommended)

```swift
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ app: UIApplication, didFinishLaunchingWithOptions opts: ...) -> Bool {
        // Register for push notifications
        UIApplication.shared.registerForRemoteNotifications()

        Task {
            do {
                let config = try await KiskisClient.shared?.fetchConfig()
                NotificationCenter.default.post(name: .kiskisReady, object: config)
            } catch {
                handleOfflineState(error)
            }
        }
        return true // Don't block main thread
    }

    // Pass push token to Kiskis
    func application(_ app: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        KiskisClient.shared?.pushToken = token
    }

    // Handle emergency config refresh
    func application(_ app: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler handler: @escaping (UIBackgroundFetchResult) -> Void) {
        if let kiskis = userInfo["kiskis"] as? [String: Any],
           kiskis["action"] as? String == "refresh" {
            Task {
                try? await KiskisClient.shared?.fetchConfig()
                handler(.newData)
            }
        }
    }
}
```

### Fallback Config (First Install Offline)

```swift
let kiskis = KiskisClient(
    teamId: "A1B2C3D4E5",
    fallbackConfig: Bundle.main.url(forResource: "fallback", withExtension: "json")
)
```

> **Warning:** Fallback configs are embedded in the binary. Never put API keys in the fallback — only non-sensitive defaults (endpoints, feature flags).

---

## Cache Policy

### How Caching Works

Three-level cache — your app never blocks on the network after the first fetch:

```
Level 1: In-Memory (instant)
  Most recent config held in a Swift property.
  Repeated fetchConfig() calls don't touch disk.

Level 2: File System (persistent across restarts)
  Written to Library/Application Support/kiskis/
  Protected by iOS sandbox + NSFileProtectionComplete
  Excluded from iCloud/iTunes backups (isExcludedFromBackup)

Level 3: Server (network fetch)
  Assertion-signed request to Kiskis.
  Only when cache is stale or missing.
```

### Cache Lifecycle

```
fetchConfig() called
  ├── In-memory cache exists and fresh? → return instantly (0ms)
  ├── File cache fresh (within TTL)? → return, refresh in background
  ├── File cache stale (past TTL, within maxStaleness)? → return with isStale=true
  ├── File cache very old (past maxStaleness)? → must fetch from server
  └── No cache (first install)? → attest + fetch, or load fallback bundle
```

### Configuration

```swift
let kiskis = KiskisClient(
    teamId: "A1B2C3D4E5",
    cachePolicy: .init(
        maxStaleness: 7 * 24 * 3600,    // Trust cache 7 days offline
        backgroundRefresh: true,          // Silent updates when online
        onStaleConfig: .warnAndUse        // .warnAndUse | .failHard | .useSilently
    )
)
```

### Cache Security

| Layer | Protection |
|-------|-----------|
| iOS Sandbox | App's Library directory is invisible to user and other apps |
| Backup Exclusion | `isExcludedFromBackup = true` — never in iTunes/iCloud backups |
| File Protection | `NSFileProtectionComplete` — iOS encrypts file when device is locked |
| Zero-Knowledge | If enabled, cached data is AES-256-GCM ciphertext |

---

## What Can You Store in a Config?

Your config is a JSON file you create. It can contain anything your app needs at runtime:

```json
{
  "api_keys": {
    "stripe": "sk_live_abc123",
    "openai": "sk-xyz789"
  },
  "endpoints": {
    "api": "https://api.myapp.com/v2",
    "cdn": "https://cdn.myapp.com"
  },
  "features": {
    "dark_mode": true,
    "max_upload_mb": 50
  },
  "images": {
    "splash_logo": "<base64 PNG, any size>"
  },
  "localization": {
    "en": { "greeting": "Hello" },
    "es": { "greeting": "Hola" },
    "ja": { "greeting": "こんにちは" }
  },
  "assets": {
    "ml_model": {
      "_type": "blob",
      "key": "model-v3.bin",
      "sha256": "a7f3b9c2...",
      "size_bytes": 5242880
    }
  }
}
```

### Size Guidance

| Size | Handling |
|------|---------|
| Small (<100KB) | Typical. Single request, fast. |
| Medium (100KB–5MB) | Works fine. Base64 images, localization, large feature flags. |
| Large (5MB+) | Use **binary blobs** instead — stored separately in S3, downloaded via presigned URLs. |

### Binary Blobs

For large files (ML models, certificate bundles, image packs), mark them with `_type: "blob"` in your config and download them individually:

```swift
let config = try await kiskis.fetchConfig()

// Find all blob references
let blobs = config.blobs()
// → [BlobReference(keyPath: "assets.ml_model", key: "model-v3.bin", sha256: "a7f3...")]

// Download to a path you choose (not into memory)
let modelPath = documentsDir.appendingPathComponent("model-v3.bin")
let savedURL = try await kiskis.downloadBlob(blobs[0], to: modelPath)
// SHA-256 is verified automatically if present in the blob reference
```

---

## Zero-Knowledge Mode

Your config is encrypted on your machine before it ever touches Kiskis servers. We store opaque ciphertext. **We cannot read your secrets — not our engineers, not a hacker, not a court order.**

### How It Works

```
Your Machine                        Kiskis Server                    Your iOS App
────────────                        ─────────────                    ────────────
CLI encrypts secrets.json           Stores encrypted                 Fetches encrypted
with your vault password            blob in S3                       blob from server
(AES-256-GCM + HKDF)               (can't read it)                  Decrypts locally
                                                                     with same password
```

### SDK Usage

```swift
// Simple (plain password)
let kiskis = KiskisClient(
    teamId: "A1B2C3D4E5",
    zeroKnowledge: .enabled(key: "MyVaultPassword")
)

// Better (derived from multiple values — harder to extract from binary)
let kiskis = KiskisClient(
    teamId: "A1B2C3D4E5",
    zeroKnowledge: .derived(components: [
        .bundleId,              // "com.myapp.weather" — already in binary, not suspicious
        .buildNumber,           // "247" — changes each build
        .custom("k8Xm"),       // short random fragment
        .custom("p2Qj"),       // another fragment
    ])
)
```

### CLI Upload

```bash
kiskis-cli upload --file secrets.json --key kk_prod_... --ver "*" \
  --encrypt --vault-pass "MyVaultPassword"
```

### Tradeoffs

| Feature | Standard Mode | Zero-Knowledge Mode |
|---------|--------------|-------------------|
| Dashboard config preview | Yes | No (encrypted blob) |
| JSON validation | Yes | No |
| Canary deployments | Yes | Yes |
| Kill switch | Yes | Yes |
| Server can read secrets | Yes | **No — mathematically impossible** |

---

## Per-User Data

Store data specific to each user — preferences, save state, custom settings. The `user_id` is any identifier from YOUR system:

| Your Auth System | What You'd Pass |
|-----------------|-----------------|
| Your own database | `userId: "usr_48291"` |
| Firebase Auth | `userId: "Xk9mP2qR4tN7"` |
| Sign in with Apple | `userId: "001234.abc..."` |
| No user system | `userId: identifierForVendor` (per-device) |

```swift
// Save
try await kiskis.saveUserData(userId: "usr_48291", data: [
    "preferences": ["theme": "dark", "language": "en"],
    "saved_items": [1, 2, 3]
])

// Load
let prefs = try await kiskis.loadUserData(userId: "usr_48291")
```

### Cross-Device Sync

If your app has user login, the same user ID is available on every device. Data syncs automatically:

```
iPhone (user_id="usr_48291")  → writes {"theme":"dark"}  → stored at hash(usr_48291)
iPad   (user_id="usr_48291")  → reads from same hash     → gets {"theme":"dark"}
```

### Apps Without User Login

Use `identifierForVendor` (per-device ID). Data works on that device but won't sync to other devices.

---

## Push Notifications

Kiskis can send push notifications to your users' devices — no Firebase, no server of your own. Send to a specific user (all their devices), a single device, or broadcast to everyone.

### Why This Matters

SwiftData and CloudKit replication can take minutes. A silent push through Kiskis triggers an immediate sync on all the user's devices, cutting wait time from minutes to seconds.

### Setup

**1. Add capabilities in Xcode:**
- Push Notifications (Signing & Capabilities)
- Background Modes → Remote notifications

**2. Register for push and hand the token to Kiskis:**

```swift
// AppDelegate.swift
func application(_ application: UIApplication,
                 didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { _, _ in }
    application.registerForRemoteNotifications()
    return true
}

func application(_ application: UIApplication,
                 didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let token = deviceToken.map { String(format: "%02x", $0) }.joined()
    KiskisClient.shared?.pushToken = token
}
```

**3. Handle incoming pushes:**

```swift
func application(_ application: UIApplication,
                 didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                 fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
    if let kiskis = userInfo["kiskis"] as? [String: Any],
       kiskis["action"] as? String == "refresh" {
        Task {
            _ = try? await KiskisClient.shared?.fetchConfig()
            completionHandler(.newData)
        }
    } else {
        // Your own push handling here
        completionHandler(.noData)
    }
}
```

**4. Associate users with devices:**

```swift
// After user logs in — enables cross-device push targeting
let recordID = try await CKContainer.default().userRecordID()
try await kiskis.setUserId(recordID.recordName)
```

### Sending Pushes

From your backend, the CLI, or the dashboard:

```bash
# Silent push to all of a user's devices (cross-device sync)
kiskis push:send --key $KEY --to "user_id" \
  --silent --data '{"action": "sync"}'

# Visible push to a single device
kiskis push:send --key $KEY --device "keyId_abc" \
  --title "Update" --body "New data available"

# Broadcast to all users
kiskis push:broadcast --key $KEY \
  --title "New feature!" --body "Dark mode is here"

# Check delivery status
kiskis push:status --key $KEY --id push_a7f3b9c2
```

Or use the REST API directly:

```bash
curl -X POST https://api.kiskis.dev/push/send \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"to":"user_id","silent":true,"data":{"action":"sync"}}'
```

### APNs Key Setup

Kiskis needs your APNs `.p8` signing key to deliver pushes. Generate one in the [Apple Developer Portal](https://developer.apple.com/account/resources/authkeys/list) under Keys → Apple Push Notifications service.

```bash
kiskis push:setup --key $KEY \
  --apns-key-file AuthKey_XXXX.p8 \
  --apns-key-id XXXX \
  --apns-team-id YOUR_TEAM_ID
```

One APNs key works for all apps in your developer account.

### Silent vs Visible

| Type | User sees it? | Best for |
|------|--------------|----------|
| Silent (`"silent": true`) | No | Data sync, config refresh, background updates |
| Visible (title + body) | Yes | Alerts, marketing, user-facing messages |

### How It Scales

Broadcasts to 50,000+ devices use SQS fan-out: the API returns immediately with a push ID, then workers process batches of 100 tokens in parallel over HTTP/2 to Apple's servers. Check progress with `/push/status/{id}`.

---

## Version Matching

Upload different configs for different app versions:

```bash
kiskis-cli upload --file default.json --key kk_prod_... --ver "*"      # all versions
kiskis-cli upload --file v2.json      --key kk_prod_... --ver "2.*"    # v2.x.x
kiskis-cli upload --file hotfix.json  --key kk_prod_... --ver "2.1.3"  # exact
```

Matching priority — **first match wins**:

| Priority | Pattern | Matches |
|----------|---------|---------|
| 1 | `2.1.3` | Exactly 2.1.3 |
| 2 | `2.1.*` | Any 2.1.x |
| 3 | `2.*` | Any 2.x.x |
| 4 | `*` | All versions |

Example: app v2.5.0 → checks `2.5.0`? no → `2.5.*`? no → `2.*`? yes → returns v2 config.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Deploy Config to Kiskis
  uses: kiskis/deploy-action@v1
  with:
    api-key: ${{ secrets.KISKIS_PROVISIONING_KEY }}
    config-file: ./config/production.json
    version: '*'
```

### Any CI System

```bash
npx kiskis-cli upload --file config.json --key $KISKIS_KEY --ver "*"
```

---

## Error Handling

```swift
do {
    let config = try await kiskis.fetchConfig()
} catch KiskisError.attestationUnavailable {
    // Device doesn't support App Attest (iOS <14, falls back to DeviceCheck)
} catch KiskisError.attestationFailed(let msg) {
    // Attestation failed — possible Apple outage or device issue
} catch KiskisError.networkError(let msg) {
    // No network and no cached config
} catch KiskisError.staleConfigRejected {
    // Cache expired and .failHard policy is set
} catch KiskisError.zeroKnowledgeDecryptionFailed {
    // Wrong vault password or tampered ciphertext
} catch KiskisError.configNotFound {
    // No config uploaded for this Team ID + Bundle ID + version
} catch KiskisError.blobDownloadFailed(let msg) {
    // Blob download error
} catch KiskisError.blobIntegrityFailed(let msg) {
    // SHA-256 mismatch on downloaded blob
}
```

---

## Sandbox vs Production

Apple has two separate attestation environments. Kiskis keeps their data completely separate — different configs, different device registries, different billing.

**Sandbox** — for development and testing. Apple's sandbox attestation server validates attestations from debug builds and the Xcode simulator. Kiskis stores sandbox device keys and configs separately from production.

**Production** — for TestFlight and App Store. Apple's production attestation server only validates attestations from real devices running release-signed binaries.

**Environment detection is server-side — you don't need to do anything.**

When a device attests, Apple embeds an `AAGUID` field in the signed attestation data:
- `appattestsandbox` → the device used Apple's sandbox attestation service
- `appattest` → the device used Apple's production attestation service

The Kiskis server reads this field directly from Apple's signed data. It cannot be faked or overridden by the client — it's part of the cryptographic attestation. The server uses it to:
1. Store the device in the correct environment partition (sandbox vs production)
2. Return the detected environment to the SDK
3. Serve configs from the matching environment's S3 path

```
Debug build on device:
  1. App Attest goes through Apple's SANDBOX attestation service
  2. Apple embeds "appattestsandbox" in the AAGUID
  3. Kiskis server reads AAGUID → detects sandbox
  4. Stores device in SANDBOX#TeamID#BundleID
  5. Serves config from s3://vault/sandbox/{hash}/manifest.json

Release build (TestFlight/App Store):
  1. App Attest goes through Apple's PRODUCTION attestation service
  2. Apple embeds "appattest" in the AAGUID
  3. Kiskis server reads AAGUID → detects production
  4. Stores device in PROD#TeamID#BundleID
  5. Serves config from s3://vault/production/{hash}/manifest.json
```

**On first launch**, the SDK uses `#if DEBUG` as a temporary hint until attestation completes. Once the server responds with the detected environment, the SDK persists it in the Keychain for all future launches. The server's detection overrides the `#if DEBUG` hint.

**You can force an environment if needed:**

```swift
let kiskis = KiskisClient(
    teamId: "A1B2C3D4E5",
    environment: .production   // Override server detection (rare)
)
```

This is rarely needed — the server detection is authoritative and correct for all normal development and release workflows.

## Testing

| Environment | Secure Enclave | Apple Attestation | Server Detects |
|-------------|----------------|-------------------|----------------|
| Xcode Simulator | No (mocked) | Sandbox | `sandbox` |
| Physical device (debug) | Yes | Sandbox | `sandbox` |
| Physical device (release) | Yes | Production | `.production` |
| TestFlight | Yes | Production | `.production` |
| App Store | Yes | Production | `.production` |

---

## Feature Highlights

| Feature | Description |
|---------|-------------|
| Hardware Attestation | Apple Secure Enclave proves genuine device on every request |
| Assertion Auth | No tokens — every request individually signed by hardware |
| Version Targeting | Different configs for `2.1.3`, `2.*`, `*` |
| Kill Switch | Instantly disable config delivery for specific versions |
| Canary Deployments | Roll out to 5% of devices, monitor, promote or rollback |
| Config Versioning | Every change archived, rollback to any revision |
| Zero-Knowledge Mode | Client-side AES-256-GCM — server can't read secrets |
| Binary Blobs | Large files via presigned S3 URLs, SHA-256 verified |
| Per-User Data | Any user identifier, cross-device sync |
| Offline Caching | 3-level cache (memory → file → server), works on subway |
| Push Notifications | Send to users, devices, or broadcast — no Firebase needed |
| Cross-Device Sync Push | Silent push triggers instant SwiftData/CloudKit refresh |
| Emergency Push | Silent APNs push forces immediate config re-fetch |
| Device Migration | Auto re-attest when user restores to new iPhone |
| Webhook Notifications | Get notified on config changes |
| Coupon System | Discount codes for billing |

## Pricing

| Plan | Monthly Active Devices | Apps | Price |
|------|----------------------|------|-------|
| Free | 1,000 | 1 | $0/mo |
| Pro | 50,000 | Unlimited | $15/mo |
| Growth | Unlimited | Unlimited | $49/mo |

Kiskis counts unique **devices**, not users. One person with iPhone + iPad = 2 devices. For most apps, device count ≈ user count.

Kiskis never breaks production apps as a billing lever. If you exceed your limit, config delivery continues — you see an upgrade prompt in the dashboard.

---

## Service

Kiskis is a hosted service at [kiskis.dev](https://kiskis.dev).

- **Dashboard:** [kiskis.dev/dashboard](https://kiskis.dev/dashboard/) — sign up, upload configs, manage keys
- **Docs:** [kiskis.dev/docs](https://kiskis.dev/docs/) — full documentation
- **Status:** [kiskis.dev/status.html](https://kiskis.dev/status.html) — service health
- **Admin:** [kiskis.dev/admin](https://kiskis.dev/admin/) — platform administration

## License

MIT — see [LICENSE](LICENSE)

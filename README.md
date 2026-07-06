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

// Team ID + config key identify which document to fetch.
// Bundle ID and app version are auto-detected.
let kiskis = KiskisClient(teamId: "A1B2C3D4E5", key: "default")
let config = try await kiskis.fetchConfig()
let stripeKey = config.string("api_keys.stripe")
```

That single call:
1. Registers the device via Apple App Attest (first launch only, 1-2 sec)
2. Signs every request with the Secure Enclave (no tokens, no passwords)
3. Fetches the config document named `key`, version-matched to the running app
4. Caches in encrypted local storage for offline use
5. Refreshes silently in the background

### What Gets Auto-Detected

| Parameter | Source | Can Override? |
|-----------|--------|---------------|
| Team ID | You provide it | Required |
| Config key | You provide it | Required (e.g. `"default"`, `"flags"`) |
| Bundle ID | `Bundle.main.bundleIdentifier` | Yes, pass `bundleId:` |
| App Version | `CFBundleShortVersionString` in Info.plist | No (always auto-detected) |
| Environment | `#if DEBUG` → sandbox, else production | Yes, pass `environment:` |

Together Team ID + Bundle ID + **key** + version form the config lookup. Each client instance is bound to one key — to read from a different config document (e.g., feature flags), create another `KiskisClient` with a different `key:`.

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
  GET /config?key=default&version=2.1.3
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
Creates provisioning credential (kk_prod_...)
Creates secrets.json on their machine
Runs: kiskis-cli upload                 Management Lambda:
  --file secrets.json                   1. Verify provisioning credential
  --auth kk_prod_...                    2. Sign TeamID.BundleID → S3 path
  --ver "*"                             3. Store at {appHash}/keys/{key}/manifest.json
  [--key flags]                         4. Encrypt at rest (KMS)
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
let config = try await KiskisClient(teamId: "A1B2C3D4E5", key: "default").fetchConfig()
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
| Replay Prevention | signCount (increments every request) + 5-minute timestamp window | Each request is unique and time-bounded |
| Transport | TLS 1.3 + Cloudflare intermediate CA pinning | Encrypted in transit, custom trust anchors rejected |

### Data Protection

| Layer | Protection |
|-------|-----------|
| **S3 vault** | SSE-KMS encryption at rest, bucket policy denies all except Lambda |
| **S3 paths** | Ed25519-signed hashes — impossible to guess or probe |
| **Provisioning credentials** | Only SHA-256 hash stored — raw value shown once at creation |
| **On-device cache** | iOS sandbox + configurable file protection class + excluded from backups |
| **Zero-Knowledge** | AES-256-GCM client-side encryption — server cannot read secrets; disk cache stores ciphertext only |

### Defense in Depth

These protections were designed, reviewed, and hardened. The short version of what was considered:

**Replay attacks.** Every assertion covers a canonical string that includes the HTTP method, path, query parameters, request body hash, your Team ID, and a Unix timestamp. The server rejects requests outside a 5-minute window and uses an atomic counter update to close the sub-millisecond TOCTOU race between checking and writing the App Attest signCount.

**Zero-Knowledge integrity.** ZK mode uses a per-customer HKDF salt derived from your Team ID and Bundle ID — two apps using the same vault password produce completely different encryption keys. The on-device cache stores only ciphertext; plaintext exists in process memory only for the lifetime of the session.

**Attestation policy.** The SDK defaults to `.requireAppAttest` and refuses to fall back to DeviceCheck. You can opt into DeviceCheck fallback explicitly, but ZK mode always overrides this and forces App Attest regardless — a weaker device cannot receive your encrypted secrets. Stale DeviceCheck key IDs from before this policy are detected and cleared at startup.

**Blob integrity.** Downloaded blobs are SHA-256 verified by default. If a blob entry in your config omits a hash, the SDK refuses the download rather than trusting it blind. Verification streams through the file in 256 KB chunks so a 1 GB ML model doesn't spike RAM.

**Keychain write failures.** Silent Keychain failures would cause re-attestation on every launch and eventually wedge a device against Apple's key-generation rate limit. Write failures are now surfaced as `KiskisError.keychainWriteFailed(OSStatus)` so you can observe and log them. The most common cause (`errSecInteractionNotAllowed` = device locked during a background write) is called out by name.

**Cache file protection.** The default (`NSFileProtectionComplete`) means the disk cache is unreadable while the device is locked, which breaks background refresh. This trade-off is documented and configurable: pass `cachePolicy: CachePolicy(fileProtection: .untilFirstUserAuthentication)` to allow background tasks to read cached config without weakening cold-boot protection.

**Bundled fallback files are plaintext in the IPA.** The `fallbackConfig:` parameter exists for offline first-launch resilience — feature flags and UI defaults, not secrets. The API surface, doc comments, and README all call this out explicitly.

**Version-targeted config is not secret-gated.** The `?version=` parameter is self-reported by the client SDK. App Attest proves the device and binary are genuine; it does not cryptographically verify the version string. Use version patterns for feature flags and non-sensitive defaults, never to gate access to secrets.

**Privacy manifest.** The SDK uses no required-reason APIs (no UserDefaults, no file timestamp reads, no system boot time, no disk space queries, no active keyboard reads). `identifierForVendor` is used client-side only to derive rollout buckets — the raw value never leaves the device. The `PrivacyInfo.xcprivacy` manifest is empty and verified correct; the reasoning is documented inline for future maintainers.

---

## iOS SDK Integration

### Basic Usage

```swift
// Team ID + config key identify the document to fetch.
let kiskis = KiskisClient(teamId: "A1B2C3D4E5", key: "default")
let config = try await kiskis.fetchConfig()

// Access values by key path
let stripe = config.string("api_keys.stripe")
let maxMB = config.int("limits.max_upload_mb")
let pricing = config.array("pricing")
let endpoints = config.dict("endpoints")
```

### Non-Blocking Init (Recommended)

```swift
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ app: UIApplication, didFinishLaunchingWithOptions opts: ...) -> Bool {
        // The SDK calls registerForRemoteNotifications() for you (autoRegisterPush,
        // on by default) — you don't need to call it here.
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

    // Forward the APNs token to Kiskis — this one line is required for push delivery.
    func application(_ app: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        KiskisClient.shared?.setPushToken(deviceToken)
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
    key: "default",
    fallbackConfig: Bundle.main.url(forResource: "fallback", withExtension: "json")
)
```

> **WARNING: Never put secrets in a fallback file.**
>
> Bundle resources are plaintext inside the IPA. Anyone who downloads your app and
> unpacks the archive can read every byte of the fallback file — there is no
> encryption path for bundled resources, and no App Attest gate protects them.
>
> Use the fallback only for values that are safe to be fully public: feature flags,
> UI copy, non-secret endpoint URLs, default thresholds. API keys, tokens, signing
> secrets, and any value that must stay confidential must come from the server.
> The whole point of Kiskis is that secrets never live in the binary.

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
    key: "default",
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
  "limits": {
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
    key: "default",
    zeroKnowledge: .enabled(vaultPass: "MyVaultPassword")
)

// Better (derived from multiple values — harder to extract from binary)
let kiskis = KiskisClient(
    teamId: "A1B2C3D4E5",
    key: "default",
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
kiskis-cli upload --file secrets.json --auth kk_prod_... --ver "*" \
  --encrypt --vault-pass "MyVaultPassword"
```

### When to use Zero-Knowledge Mode

**Use ZK mode for any secret where a mass leak would be catastrophic.**

In Standard mode, your configs are encrypted at rest in S3 with KMS, and only the Lambda role can read them. That's strong protection — but a sufficiently sophisticated attacker who compromises the Kiskis backend (AI-assisted exploit, supply chain attack, credential leak) could exfiltrate plaintext configs across all customers simultaneously. The Lambda role can read S3, so anything it can access, a compromised Lambda can send out.

Zero-Knowledge mode eliminates that risk entirely. Even a complete backend compromise — every Lambda, every S3 bucket, every employee credential — yields nothing but encrypted garbage. The math won't allow it.

Practical guidance:
- **Stripe live keys, OpenAI keys, payment credentials** → ZK mode. A mass leak means every customer's payment integration is compromised at once.
- **Feature flags, API endpoints, non-secret config** → Standard mode is fine. Losing these in a breach is annoying, not catastrophic.
- **The binary key trade-off**: In ZK mode the decryption key lives in your app binary. A targeted reverse-engineering attack against *your specific app* can extract it. This is a different threat profile — laborious, per-app, doesn't scale. The backend attack ZK defends against *does* scale: one exploit, every customer.

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

### Device-User Binding

The first `userId` a device uses is permanently bound to that device's App Attest key. Every subsequent call — `saveUserData`, `loadUserData`, and `setUserId` — must present the same `userId` or the server returns a 403.

```
Device installs → calls saveUserData(userId: "usr_48291") → bound to "usr_48291"
Same device     → calls saveUserData(userId: "usr_99999") → 403 Forbidden
```

**This is intentional.** It prevents a genuine device from reading or writing another user's data by supplying a different identifier. App Attest proves the device is real; this binding proves it's acting on behalf of the same user it always has.

**User logs out and logs in as someone else:** the device is already bound. The new user will get a 403 until the app is reinstalled (which generates a fresh App Attest key). If your app supports account switching, call `setUserId` once at first login and do not change it on that install.

**Cross-device sync still works:** a second device with no prior binding can freely claim the same `userId` and read the same data. Binding blocks *switching*, not *sharing*.

---

## Feature Flags

Kiskis is a feature flag system. Ship features dark, toggle them on/off, roll them out gradually — all without an app release. Same SDK you already use for API keys.

### Why This Matters

LaunchDarkly starts at $200/mo. Firebase Remote Config locks you into the Firebase ecosystem. Kiskis includes flags on every tier — free for 500 MAU (Hobby), $29/mo for 5,000 MAU (Indie) — and they work with the same config, same dashboard, same cache, same attestation.

### The Simplest Flag

Flags live in a dedicated config document under a key of your choosing — typically `"flags"`. Bind a `KiskisClient` instance to that key. **Flag names sit at the top level of the document** — there is no `features.` prefix.

```json
{
  "dark_mode": true,
  "new_checkout": false,
  "beta_search": true
}
```

In Swift, use a separate client bound to the `"flags"` key:

```swift
let flags = KiskisClient(teamId: "A1B2C3D4E5", key: "flags")
_ = try await flags.fetchConfig()

if flags.isEnabled("dark_mode") {
    enableDarkMode()
}

if flags.isEnabled("new_checkout", default: false) {
    showNewCheckout()
}
```

`isEnabled("dark_mode")` reads the top-level `dark_mode` field of the flags document. The `default` value is returned if the config hasn't loaded yet (first launch offline). After the first successful fetch, flags work offline from cache.

> **Why a separate client?** Each `KiskisClient` is bound to one config key. Your API keys (in `"default"`) and feature flags (in `"flags"`) are independent documents with independent version histories and kill switches. Use two clients — one per key.

### Variants (Multi-Way Flags)

Flags don't have to be booleans. Use strings for A/B tests or multi-way splits:

```json
{ "checkout_flow": "express" }
```

```swift
switch flags.variant("checkout_flow", default: "classic") {
case "express":  showExpressCheckout()
case "onepage":  showOnePageCheckout()
default:         showClassicCheckout()
}
```

### Progressive Rollouts

Enable a feature for a percentage of devices. The same device always gets the same answer for the same flag (deterministic hash of flag name + `identifierForVendor`):

```swift
// Ship to 25% of devices
if flags.isInRollout("new_search", percentage: 25) {
    useNewSearchAPI()
}
```

Put the percentage in the flags document if you want to ramp from the dashboard without shipping an update:

```swift
let pct = (try await flags.fetchConfig()).int("new_search_rollout_pct") ?? 0
if flags.isInRollout("new_search", percentage: pct) { ... }
```

### Kill Switch

A flag goes wrong in production. Three ways to turn it off:

1. **Flip in dashboard** — set `broken_thing` to `false` in the flags document, save. Online devices pick it up within the TTL (default 1 hour).
2. **Pair with push** — `kiskis push:broadcast --auth $AUTH --silent --data '{"action":"refresh"}'` — every device refetches within seconds.
3. **Version kill switch** — `POST /admin/kill-switch` disables config delivery for a specific key + version, forcing cached fallback.

### Version-Targeted Flags

Different flag values for different app versions (within the `flags` key):

```bash
kiskis upload --file v1-flags.json --auth $AUTH --key flags --ver "1.*"
kiskis upload --file v2-flags.json --auth $AUTH --key flags --ver "2.*"
```

Useful when a feature depends on v2-only code. v1 users get the v1 file (flag off), v2 users get the v2 file (flag on).

Note: version is client-asserted (see the warning in Version Matching above). Use version targeting for flags and defaults, never for secrets.

### Staff / Beta Overrides

Enable a flag for specific users before rolling out widely:

```swift
// Global default lives in the flags document: "beta_search": false

// Store per-user override via dashboard, CLI (`kiskis user:set`), or API
try await flags.saveUserData(userId: "staff_alice", data: [
    "feature_overrides": ["beta_search": true]
])

// In your app
let userData = try await flags.loadUserData(userId: currentUserId)
let override = (userData?["feature_overrides"] as? [String: Bool])?["beta_search"]
let isOn = override ?? flags.isEnabled("beta_search")
```

### The Gradual Rollout Pattern

Launch a feature safely in four steps:

1. **Ship it dark.** Upload config with the flag `false`. Feature code is in the app but not reachable.
2. **Enable for staff.** Per-user overrides for internal testers. Verify in production with real data.
3. **5% rollout.** Monitor crash rates, latency, user feedback. If bad, flip to 0% — no release needed.
4. **Ramp up.** 5% → 25% → 50% → 100% over days or weeks. Any issue, flip back.

### Kiskis vs Dedicated Flag Services

| Feature | Kiskis | LaunchDarkly | Firebase Remote Config |
|---------|--------|--------------|------------------------|
| Starter price | **$29/mo Indie** | $200+/mo | Free (Firebase lock-in) |
| On/off flags | ✓ | ✓ | ✓ |
| Variants / A/B | ✓ | ✓ | ✓ |
| Progressive rollout | ✓ | ✓ | Limited |
| Kill switch | ✓ | ✓ | ✓ |
| Rollback history | ✓ | ✓ | Limited |
| Hardware attestation | ✓ | ✗ | Partial |
| Real-time updates | Push-triggered | SSE streaming | Polling |
| Server-side rule engine | ✗ (client-side) | ✓ | ✓ |
| Evaluation metrics | Your analytics | ✓ | ✓ |
| Also delivers API keys | ✓ | ✗ | ✗ |

**Use LaunchDarkly if** you need a server-side rule engine (target by country + subscription + custom attributes), formal A/B testing with outcome measurement, or built-in evaluation dashboards. **Use Kiskis if** you need on/off flags, variants, and gradual rollouts without enterprise pricing — and you want the same tool for API keys, config, and flags.

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
// After user logs in — enables cross-device push targeting.
// Call once per install. This permanently binds the device to this userId;
// subsequent calls with a different userId return 403 (see Device-User Binding).
let recordID = try await CKContainer.default().userRecordID()
try await kiskis.setUserId(recordID.recordName)
```

### Sending Pushes

From your backend, the CLI, or the dashboard:

```bash
# Silent push to all of a user's devices (cross-device sync)
kiskis push:send --auth $AUTH --to "user_id" \
  --silent --data '{"action": "sync"}'

# Visible push to a single device
kiskis push:send --auth $AUTH --device "keyId_abc" \
  --title "Update" --body "New data available"

# Broadcast to all users
kiskis push:broadcast --auth $AUTH \
  --title "New feature!" --body "Dark mode is here"

# Check delivery status
kiskis push:status --auth $AUTH --id push_a7f3b9c2
```

Or use the REST API directly:

```bash
curl -X POST https://api.kiskis.dev/push/send \
  -H "Authorization: Bearer $AUTH" \
  -H "Content-Type: application/json" \
  -d '{"to":"user_id","silent":true,"data":{"action":"sync"}}'
```

### APNs Key Setup

Kiskis needs your APNs `.p8` signing key to deliver pushes. Generate one in the [Apple Developer Portal](https://developer.apple.com/account/resources/authkeys/list) under Keys → Apple Push Notifications service.

```bash
kiskis push:setup --auth $AUTH \
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

## Key + Version

Each app can hold multiple **named config documents** (identified by `key`), and each key has its **own independent** set of version-targeted payloads. The lookup is always `(key, version)`.

### Multiple Keys per App

```bash
# Main runtime config
kiskis-cli upload --file config.json --auth kk_prod_... --ver "*"                  # key defaults to "default"

# Feature flags document
kiskis-cli upload --file flags.json  --auth kk_prod_... --ver "*" --key flags

# Promotional copy
kiskis-cli upload --file promos.json --auth kk_prod_... --ver "*" --key promos
```

Your SDK reads one key per `KiskisClient` instance:

```swift
let runtime = KiskisClient(teamId: "A1B2C3D4E5", key: "default")
let flags   = KiskisClient(teamId: "A1B2C3D4E5", key: "flags")
```

Requesting a key that doesn't exist returns a 404. There is no fallback across keys.

### Version Matching Within a Key

Upload different configs for different app versions **within the same key**:

```bash
kiskis-cli upload --file default.json --auth kk_prod_... --ver "*"      # all versions
kiskis-cli upload --file v2.json      --auth kk_prod_... --ver "2.*"    # v2.x.x
kiskis-cli upload --file hotfix.json  --auth kk_prod_... --ver "2.1.3"  # exact
```

Matching priority — **first match wins**:

| Priority | Pattern | Matches |
|----------|---------|---------|
| 1 | `2.1.3` | Exactly 2.1.3 |
| 2 | `2.1.*` | Any 2.1.x |
| 3 | `2.*` | Any 2.x.x |
| 4 | `*` | All versions |

Example: app v2.5.0 → checks `2.5.0`? no → `2.5.*`? no → `2.*`? yes → returns v2 config. Matching happens independently for each key.

> **WARNING: Version is client-asserted — never gate secrets on it.**
>
> App Attest proves the device is genuine Apple hardware running an unmodified binary.
> It does NOT prove the version number: the `?version=` value comes from
> `Bundle.main.infoDictionary` on the client, and the server has no cryptographic
> receipt for it. A device can claim any version and receive that variant's payload.
>
> Version patterns are safe for non-security decisions:
> - Feature flags that enable/disable version-specific UI
> - Config that references v2-only code paths
> - Non-sensitive defaults that differ between releases
>
> Never put API keys, tokens, signing secrets, or any confidential value in a
> version-specific variant expecting that older-version devices won't receive it.
> If you need to deliver different secrets to different cohorts, provision separate
> config keys per cohort and control access at the key level.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Deploy Config to Kiskis
  uses: kiskis/deploy-action@v1
  with:
    auth: ${{ secrets.KISKIS_AUTH }}
    config-file: ./config/production.json
    key: 'default'
    version: '*'
```

### Any CI System

```bash
npx kiskis-cli upload --file config.json --auth $KISKIS_AUTH --ver "*"
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
    // No config uploaded for this Team ID + Bundle ID + key + version
    // (404 when the requested key doesn't exist — no cross-key fallback)
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
    key: "default",
    environment: .production   // Override server detection (rare)
)
```

This is rarely needed — the server detection is authoritative and correct for all normal development and release workflows.

## Testing

### Testing Matrix

| Environment | Secure Enclave | Bypass Secret | App Attest |
|-------------|----------------|---------------|-----------|
| Xcode Simulator | No — not supported | Active when set | N/A (bypass) |
| Physical device (debug build) | Yes | Compiled out — ignored | Sandbox |
| Physical device (release build) | Yes | Compiled out — ignored | Production |
| TestFlight | Yes | Compiled out — ignored | Production |
| App Store | Yes | Compiled out — ignored | Production |

The bypass is **Simulator-only** (SDK 0.1.2+). It is compiled out of every build that
runs on real hardware — including debug builds on device — so setting the env var never
affects a device build.

### Simulator & CI: The Bypass Secret

iOS Simulator has no Secure Enclave. Apple App Attest requires hardware attestation — it cannot run in the Simulator or on Linux CI runners (GitHub Actions, Bitrise, etc.). Without a solution, `fetchConfig()` throws `attestationUnavailable` in every simulator run.

The **bypass secret** solves this — for the Simulator only. It is a per-team credential that lets **Simulator** builds skip App Attest and authenticate via a shared secret instead.

#### The bypass is Simulator-only, not "debug-only"

This is the most important thing to understand, and the most common source of confusion. As of SDK **0.1.2** the bypass code is gated on `#if DEBUG && targetEnvironment(simulator)`. `targetEnvironment(simulator)` is a **compile-time** condition that is true only when the build destination is a Simulator:

- **Simulator build** → the bypass code is present and activates when `KISKIS_BYPASS_SECRET` is set.
- **Any build that runs on a real device** (debug, release, TestFlight, App Store) → the bypass code is **physically compiled out**. The app always runs real App Attest, even if `KISKIS_BYPASS_SECRET` is set in the environment. A device has a Secure Enclave, so it doesn't need — and can't use — the bypass.

**A debug build on device does NOT use the bypass.** "Debug" is not the trigger; "running in the Simulator" is. This is why a debug build on your phone with the env var set still performs real attestation.

**You can therefore set `KISKIS_BYPASS_SECRET` once and leave it.** Put it in your scheme's environment variables and forget it — it activates in the Simulator and is inert on device. No per-run scheme editing, no separate "device" and "simulator" schemes.

> **Upgrade note:** before 0.1.2 the gate was `#if DEBUG` alone, so a *device* debug build with the env var set would incorrectly send bypass headers instead of a real assertion — and production rejects bypass tokens, producing a `401` / "Re-attestation failed". If you see that, upgrade to 0.1.2+ (and/or clear the env var for device runs).

**Security guarantees (two independent layers):**

1. **Client:** the bypass is gated on `targetEnvironment(simulator)`, so the code to send a bypass token does not exist in any build that runs on real hardware. An attacker who obtains the secret cannot use it from a device build — the code isn't there.
2. **Server:** the delivery Lambda only honors bypass tokens on non-production stacks (`ALLOW_DEV_TOKENS === 'true' && STACK_ENV !== 'prod'`, and only for `X-Environment: sandbox`). A bypass token can **never** authenticate against production, even if one were somehow sent.

#### How It Works

```
Simulator (build destination = Simulator), with KISKIS_BYPASS_SECRET set:
  SDK reads KISKIS_BYPASS_SECRET from process environment
  → sends X-Bypass-Token: <secret>, X-Team-Id, X-Bundle-Id headers
  → non-prod server looks up SHA-256(secret) in DynamoDB under BYPASS#{teamId}
  → if match: returns config (authenticated as simulator for this team)
  → if no match, or a prod stack: falls through to assertion verification → 401

Any device build (debug, release, TestFlight, App Store):
  Bypass code is compiled out. The app always runs the real App Attest
  assertion flow; KISKIS_BYPASS_SECRET is ignored even if present.
```

#### Step 1: Generate a Bypass Secret

In the Kiskis dashboard, go to the **Keys** tab and scroll to the **Developer Bypass Secret** section. Enter your Apple Team ID and click **Generate Secret**.

The raw secret (`kk_dev_...`) is shown once and never stored server-side. Copy it immediately.

Alternatively, use the CLI:

```bash
# Not yet available — use the dashboard for now
```

#### Step 2: Configure Xcode Simulator

Open your scheme editor: **Product → Scheme → Edit Scheme → Run → Arguments → Environment Variables**.

Add a new environment variable:

| Name | Value |
|------|-------|
| `KISKIS_BYPASS_SECRET` | `kk_dev_your_secret_here` |

The SDK reads this variable at runtime. Your Simulator builds will now fetch real config from the server, exactly as a real device would.

**Set it once and leave it.** On 0.1.2+ the variable is inert on device (the bypass code is compiled out), so you do not need to remove it before running on hardware or cutting a release — there's no separate "device" scheme to maintain.

> **Secret hygiene:** a *shared* scheme is committed to git, which would leak the secret. Keep the scheme **unshared** (per-developer, under `xcuserdata/`, gitignored), or store the value in a gitignored `.xcconfig` and reference it — don't commit the raw `kk_dev_...` value.

#### Step 3: Configure GitHub Actions / CI

Add the secret to your repository: **Settings → Secrets and variables → Actions → New repository secret**.

Name: `KISKIS_BYPASS_SECRET`
Value: `kk_dev_your_secret_here`

Then pass it as an environment variable in your workflow step:

```yaml
- name: Run tests
  env:
    KISKIS_BYPASS_SECRET: ${{ secrets.KISKIS_BYPASS_SECRET }}
  run: xcodebuild test -scheme MyApp -destination 'platform=iOS Simulator,name=iPhone 16'
```

#### Step 4: No SDK Changes Needed

The SDK automatically detects `KISKIS_BYPASS_SECRET` in the process environment. No code changes are required — the same `fetchConfig()` call that works on a real device also works in the Simulator once the env var is set.

```swift
// This exact code works identically on a real device AND in the Simulator
// (with KISKIS_BYPASS_SECRET set in the scheme environment)
let kiskis = KiskisClient(teamId: "A1B2C3D4E5", bundleId: "com.myapp.weather")
let config = try await kiskis.fetchConfig()
```

#### Revoking a Bypass Secret

If a bypass secret is compromised, revoke it immediately from the dashboard (**Keys → Developer Bypass Secret → Revoke Secret**). The revocation is instant — the DynamoDB item is deleted and any subsequent request with the old secret falls through to assertion verification, which fails (no Secure Enclave on the simulator).

After revoking, generate a new secret and update your Xcode scheme and CI secrets.

#### What the Bypass Does NOT Do

- It does not affect any build that runs on real hardware — the Simulator-only code is compiled out of every device build (debug, release, TestFlight, App Store) by `#if DEBUG && targetEnvironment(simulator)`.
- It does not bypass rate limiting or billing — requests are counted normally.
- It does not grant access to other teams' data — the secret is scoped to a specific Apple Team ID.
- It does not enable Zero-Knowledge decryption — the SDK still needs the vault key you provided for that.

---

## Feature Highlights

| Feature | Description |
|---------|-------------|
| Hardware Attestation | Apple Secure Enclave proves genuine device on every request |
| Assertion Auth | No tokens — every request individually signed by hardware |
| Version Targeting | Different configs for `2.1.3`, `2.*`, `*` |
| Kill Switch | Instantly disable config delivery for specific versions |
| Feature Flags | `isEnabled()`, `variant()`, `isInRollout()` — LaunchDarkly-style flags built in |
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
| Simulator / CI Bypass | Simulator-only bypass secret (`#if DEBUG && targetEnvironment(simulator)`) — skip App Attest in the Simulator and CI; compiled out of every device build |

## Pricing

All features on every tier. Pay for scale of users, not the feature set.

| Plan | Monthly Active Devices | Apps | Price |
|------|----------------------|------|-------|
| Hobby | 500 | 1 | $0/mo |
| Indie | 5,000 | Unlimited | $29/mo |
| Pro | 25,000 | Unlimited | $99/mo |
| Growth | 100,000 | Unlimited | $249/mo |
| Scale | 100k+ | Unlimited | Custom — [contact us](mailto:sales@kiskis.dev) |

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

# EA Origin Wire Format (v0.5.2)

**Status:** VERIFIED via disassembly of Activation64.dll's 2 unnamed exports + public EA Origin SDK docs.

**Source:** `Input/lost-in-random/Core/Activation64.dll` (3 MB PE32+ for x86-64, 6 sections)

**Disassembly findings:** see `data/wire_sigs/lir.json` (the 2 export functions at RVA 0x7b10 + 0x75c0 + the X.509 token parser + the URL path parsing with 0x2f '/' and 0x5c '\' byte references).

---

## 1. Named-pipe (in-proc token exchange)

`\\.\pipe\OriginClientService`

The canonical in-proc token exchange channel between the LIR launcher and the Origin client. The launcher issues an `OpenFile` / `CreateFile` on this pipe + writes a token + reads a response. The response is an EA Atom-format auth token (X.509 cert + JSON body).

**Implementation note:** Python's named-pipe support on Linux is via `multiprocessing` + `asyncio` only. The v0.5.2 emulator implements the HTTP endpoints (which the launcher actually uses post-pipe); the named-pipe simulation is a future work item.

---

## 2. HTTP endpoints

### 2.1 `GET /origin/v1/health`

The emulator's health endpoint (backward-compatibility with the v0.5.0 stub).

**Response:**
```json
{
  "status": "ok",
  "service": "origin-emulator",
  "version": "0.3.0",
  "build": "re-breaker-0.3.0"
}
```

### 2.2 `POST /atom/token` (auth)

The EA Atom-format auth endpoint. The client POSTs a `grant_type=external_auth` form-encoded body with an `external_auth_type=openid_connect` + `external_auth_token=<token>` payload.

**Request:**
```
POST /atom/token HTTP/1.1
Host: auth.origin.com
Content-Type: application/x-www-form-urlencoded

grant_type=external_auth&external_auth_type=openid_connect&external_auth_token=<token>
```

**Response (200):**
```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "expires_in": 3600,
  "token_type": "Bearer",
  "account_id": "00000000-0000-0000-0000-000000000010",
  "user_id": "00000000-0000-0000-0000-000000000010",
  "display_name": "operator@re-breaker.lab.local"
}
```

**Response (401 — invalid grant):**
```json
{
  "error": "invalid_grant",
  "error_description": "external_auth_token not recognized"
}
```

### 2.3 `GET /atom/users/me` (user info)

The user info endpoint. Requires `Authorization: Bearer <access_token>`.

**Request:**
```
GET /atom/users/me HTTP/1.1
Host: api.origin.com
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "userId": "00000000-0000-0000-0000-000000000010",
  "personaId": "00000000-0000-0000-0000-000000000010",
  "email": "operator@re-breaker.lab.local",
  "displayName": "Operator",
  "country": "US",
  "language": "en",
  "subscribeToUpdates": true,
  "lastLoginDate": "2026-01-01T00:00:00Z"
}
```

### 2.4 `GET /atom/entitlements` (entitlements)

The entitlement list endpoint. Requires `Authorization: Bearer <access_token>`. Returns the user's owned products.

**Request:**
```
GET /atom/entitlements?user_id=<id> HTTP/1.1
Host: entitlement.origin.com
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "userId": "00000000-0000-0000-0000-000000000010",
  "entitlements": [
    {
      "entitlementId": "<uuid>",
      "productId": "lir-prod",
      "productName": "Lost In Random",
      "grantDate": "2026-01-01T00:00:00Z",
      "status": "ACTIVE",
      "isConsumable": false,
      "entitlementTag": "OWNED",
      "version": 1
    }
  ]
}
```

### 2.5 `POST /atom/activation` (activation)

The product activation endpoint. The client POSTs an `activation_code` + `product_id` to claim a product.

**Request:**
```
POST /atom/activation HTTP/1.1
Host: activation.origin.com
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "activation_code": "<code>",
  "product_id": "lir-prod"
}
```

**Response (200):**
```json
{
  "status": "success",
  "activation_id": "<uuid>",
  "entitled": true,
  "product_id": "lir-prod",
  "activated_at": "2026-06-09T12:00:00Z"
}
```

---

## 3. Internal canonical endpoints (the public `core` endpoints)

### 3.1 `GET /core/v1/products/<product_id>` (product metadata)

The product metadata endpoint. Returns the canonical product record for a given product.

**Response (200):**
```json
{
  "productId": "lir-prod",
  "productName": "Lost In Random",
  "publisher": "Electronic Arts",
  "sku": "EA-LIR-STD",
  "platforms": ["PC", "MAC", "PS4", "PS5", "XBOX"],
  "releaseDate": "2021-09-10",
  "genres": ["Action", "Adventure", "Roguelike"]
}
```

### 3.2 `GET /core/v1/users/<user_id>/entitlements/<product_id>` (per-product entitlement)

The per-product entitlement endpoint. Returns the specific user's entitlement for a specific product.

**Response (200):**
```json
{
  "userId": "00000000-0000-0000-0000-000000000010",
  "productId": "lir-prod",
  "entitled": true,
  "subscriptionTier": "full",
  "entitlementId": "<uuid>",
  "grantedAt": "2026-01-01T00:00:00Z",
  "expiresAt": null
}
```

---

## 4. Implementation notes for the v0.5.2 Origin emulator

The Origin emulator implements the 5 HTTP endpoints above (auth, user, entitlements, activation, health) + the 2 internal canonical endpoints (product metadata + per-product entitlement). The named-pipe is documented but not implemented in v0.5.2 (future work item, requires a real Windows host for the actual `\\.\pipe\OriginClientService` semantics).

The emulator returns a HMAC-signed JWT access token (using the same `cryptography` library pattern as the SEGA SSO emulator). The `EAJSON/TokenBuffer` strings in the binary confirm the EA Atom protocol is JSON-based (the v0.4.1.9 plan's "core endpoints" deliverable).

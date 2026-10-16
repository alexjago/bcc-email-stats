# BCC email stats

A compact Cloudflare Worker that counts emails sent with an address such as
`housing-abc123@stats.example.org` in BCC. It uses Cloudflare Email Routing for
ingress and D1 for durable, queryable event data.

It deliberately stores no raw email bodies, subjects, sender addresses, or BCC
tokens. A supplied unique token is stored only as a SHA-256 fingerprint.

## Address format

```
<campaign-id>[-<unique-id>[.<hmac>]]@<your-domain>
```

Examples:

```
housing@stats.example.org
housing-contact_123@stats.example.org
housing-contact_123.V1P6zsnqI0WQxXDRxC7vJ18Ze1dltXXZ4YwM0YxHE-I@stats.example.org
```

`campaign-id` accepts lower-case letters, digits, and underscores. It cannot
contain `-`, which keeps the requested hyphen-delimited format unambiguous.
Unique IDs can contain lower-case letters, digits, `_`, and `-`.

When enabled, the HMAC is base64url-encoded HMAC-SHA-256 over:

```
<campaign-id>:<unique-id>
```

## Set up

1. Install packages: `npm install`.
2. Create D1: `npm run d1:create`. Copy the printed `database_id` into
   `wrangler.jsonc`.
3. Replace `stats.example.org` in `wrangler.jsonc` with the Cloudflare-managed
   domain that will receive BCC mail. The `addresses` entry creates a catch-all
   route when deployed.
4. Apply the schema: `npm run d1:migrate:remote`.
5. Set secrets (never place these in `wrangler.jsonc`):

   ```sh
   npx wrangler secret put STATS_API_TOKEN
   npx wrangler secret put RECIPIENT_HMAC_SECRET
   ```

6. To require signed recipient tokens, add this non-secret setting to
   `wrangler.jsonc`:

   ```json
   "vars": { "REQUIRE_RECIPIENT_SIGNATURE": "true" }
   ```

7. Generate types and deploy:

   ```sh
   npm run cf-types
   npm run check
   npm run deploy
   ```

Cloudflare must have Email Routing enabled for the destination domain. A BCC
address needs only to be syntactically valid; the Worker processes the envelope
recipient in `message.to`.

## Read stats

All stats endpoints require `Authorization: Bearer <STATS_API_TOKEN>`.

```sh
curl -H "Authorization: Bearer $STATS_API_TOKEN" https://<worker-url>/api/campaigns
curl -H "Authorization: Bearer $STATS_API_TOKEN" https://<worker-url>/api/campaigns/housing
```

`total` counts delivered messages; `unique_recipients` counts distinct supplied
unique IDs. Messages without a unique ID contribute to `total` but not the
unique-recipient value. The `Message-ID` header is used to avoid counting a
replayed message twice when available.

## Signature snippet

Generate the optional recipient signature in a trusted service, never in the
public mailto page:

```js
const input = `${campaignId}:${uniqueId}`;
const key = await crypto.subtle.importKey(
  "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
);
const bytes = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input)));
const signature = btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
const bcc = `${campaignId}-${uniqueId}.${signature}@stats.example.org`;
```

## Security choices

- The stats API is bearer-token protected; put it behind Cloudflare Access too
  if more than one person needs access.
- Start with unsigned addresses for low-friction counting. Turn on mandatory
  HMACs if external senders could fabricate campaign counts.
- The Worker does not forward received mail. It records the event then ends the
  route, so no email content is retained by the application.

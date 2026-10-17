# Inventory API v2: design notes

Drafted at {{CANARY_TEAMMATE}}'s place, {{CANARY_ADDRESS}}, after the warehouse visit.

## API decisions

1. Pagination is cursor-based: every list returns an opaque `next_cursor`; page size is capped at 200.
2. Idempotency: every POST takes an `Idempotency-Key` header; a replay returns the first response.
3. Versioning: all routes move under a `/v2/` prefix; v1 is sunset six months after launch.

## Open questions

- {{CANARY_TEAMMATE}} to confirm rate limits with the warehouse team.

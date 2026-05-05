#!/usr/bin/env bash
# strfry writePolicy plugin — accept only the kinds Pricoin's
# orderbook and DM transport actually use. Everything else is
# rejected at ingest so the relay's storage stays focused.
#
# Plugin protocol: strfry pipes a JSON line per inbound event;
# we respond with a one-line JSON verdict.

while IFS= read -r line; do
    kind=$(printf '%s' "$line" | jq -r '.event.kind // empty' 2>/dev/null)
    case "$kind" in
        # 4     — NIP-04 encrypted direct messages (peer DMs).
        # 5     — NIP-09 deletes (allow users to retract offers).
        # 30030 — Pricoin orderbook offers (parameterized replaceable).
        4|5|30030)
            printf '{"id":%s,"action":"accept"}\n' \
                "$(printf '%s' "$line" | jq '.event.id')"
            ;;
        *)
            printf '{"id":%s,"action":"reject","msg":"blocked: pricoin relay only accepts kinds 4, 5, 30030"}\n' \
                "$(printf '%s' "$line" | jq '.event.id')"
            ;;
    esac
done

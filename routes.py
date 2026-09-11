"""HTTP surface for the policy engine.

Route map:
  GET    /policies                 list policies (optional ?domain=)
  PATCH  /policies/<id>            signed edit path — re-signs on write
  POST   /events                   fire an event through evaluate()
  GET    /audit-chain              list the hash-linked audit blocks
  POST   /audit-chain/verify       recompute + verify chain integrity
  GET    /quarantine               list contained items
  POST   /quarantine/<id>/release  release from containment (gated)
  POST   /admin/rogue-edit/<id>    demo-only: mutate a policy WITHOUT
                                    re-signing, to exercise tamper
                                    detection. Disabled unless the app
                                    is running with DEBUG=True.

Anything that *loosens* enforcement — setting a policy's action to
"allow", or releasing an item from quarantine — requires the
X-Discernment-Key header to match app.config["DISCERNMENT_KEY"]. A
valid signature alone is never enough for those two operations.
"""
from flask import Blueprint, current_app, jsonify, request

from app import db
from app.crypto import chain_block_hash, sign_policy
from app.engine import evaluate

bp = Blueprint("arachnode", __name__)


def _discernment_ok(req) -> bool:
    supplied = req.headers.get("X-Discernment-Key", "")
    return supplied != "" and supplied == current_app.config["DISCERNMENT_KEY"]


def _append_block(kind, domain, action, explanation, policy_id=None, policy_name=None):
    prev_hash = db.last_audit_hash()
    content = {
        "domain": domain, "action": action, "explanation": explanation,
        "policy_id": policy_id, "policy_name": policy_name,
    }
    block_hash = chain_block_hash(prev_hash, content)
    db.append_audit_block(kind, domain, action, explanation, prev_hash, block_hash,
                           policy_id, policy_name)


# ---------------------------------------------------------------- policies

@bp.get("/policies")
def list_policies():
    rows = db.list_policies(domain=request.args.get("domain"))
    return jsonify([db.policy_row_to_dict(r) for r in rows])


@bp.patch("/policies/<policy_id>")
def patch_policy(policy_id):
    """The signed write path. Any successful call here re-signs the
    policy with the server's secret, so the engine will trust and
    enforce the result exactly as written."""
    row = db.get_policy(policy_id)
    if row is None:
        return jsonify({"error": f"no such policy: {policy_id}"}), 404
    current = db.policy_row_to_dict(row)

    body = request.get_json(silent=True) or {}
    is_loosening = body.get("action") == "allow" or (body.get("enabled") is True and not current["enabled"])

    if is_loosening and not _discernment_ok(request):
        return jsonify({
            "error": "discernment_key_required",
            "message": (
                f"Setting '{current['name']}' to allow (or re-enabling it) loosens enforcement "
                "and needs the Discernment Key, not just a valid API call."
            ),
        }), 403

    updated = dict(current)
    updated.update({k: v for k, v in body.items() if k in
                     ("name", "priority", "enabled", "action", "conditions")})
    signature = sign_policy(updated, current_app.config["SIGNING_SECRET"])

    row = db.update_policy_fields(policy_id, body, signature)
    return jsonify(db.policy_row_to_dict(row))


# ---------------------------------------------------------------- events

@bp.post("/events")
def fire_event():
    body = request.get_json(silent=True) or {}
    domain = body.get("domain")
    payload = body.get("payload", {})
    if domain not in ("access", "threat", "data_governance"):
        return jsonify({"error": "domain must be one of access, threat, data_governance"}), 400

    policies = [db.policy_row_to_dict(r, include_signature=True)
                for r in db.list_policies(domain=domain)]
    decision = evaluate(domain, payload, policies, current_app.config["SIGNING_SECRET"])

    _append_block("decision", domain, decision.action, decision.explanation,
                  decision.policy_id, decision.policy_name)

    if decision.action in ("quarantine", "capture"):
        import json as _json
        ref = "unknown"
        for key in ("agent", "artifact", "actor", "source_ip"):
            if key in payload:
                v = payload[key]
                ref = str(v.get("name") or v.get("id") or _json.dumps(v)) if isinstance(v, dict) else str(v)
                break
        db.add_quarantine_item(ref, domain, "captured" if decision.action == "capture" else "quarantined")

    alerts = []
    for tampered_id in decision.tampered:
        policy_row = db.get_policy(tampered_id)
        name = policy_row["name"] if policy_row else tampered_id
        alert_text = (
            f'SECURITY ALERT: policy "{name}" failed signature verification and was '
            "ignored during evaluation — possible unauthorized modification."
        )
        _append_block("alert", domain, "alert", alert_text)
        alerts.append(alert_text)

    result = decision.as_dict()
    result["alerts"] = alerts
    return jsonify(result)


# ---------------------------------------------------------------- audit chain

@bp.get("/audit-chain")
def get_audit_chain():
    rows = db.list_audit_blocks()
    return jsonify([db.audit_block_to_dict(r) for r in rows])


@bp.post("/audit-chain/verify")
def verify_audit_chain():
    rows = db.list_audit_blocks()
    running = "0" * 64
    broken_at = None
    for row in rows:
        expected = chain_block_hash(running, db.audit_block_content(row))
        if expected != row["hash"] or row["prev_hash"] != running:
            broken_at = row["idx"]
            break
        running = row["hash"]
    if broken_at is None:
        return jsonify({"verified": True, "blocks": len(rows)})
    return jsonify({"verified": False, "blocks": len(rows), "broken_at": broken_at})


# ---------------------------------------------------------------- quarantine

@bp.get("/quarantine")
def list_quarantine():
    rows = db.list_quarantine()
    return jsonify([db.quarantine_row_to_dict(r) for r in rows])


@bp.post("/quarantine/<int:item_id>/release")
def release_quarantine(item_id):
    row = db.get_quarantine_item(item_id)
    if row is None:
        return jsonify({"error": f"no such quarantine item: {item_id}"}), 404
    if row["status"] == "released":
        return jsonify(db.quarantine_row_to_dict(row))

    if not _discernment_ok(request):
        return jsonify({
            "error": "discernment_key_required",
            "message": (
                f"Release refused for '{row['ref']}' — a service signature alone cannot let "
                "something out of containment. Supply X-Discernment-Key."
            ),
        }), 403

    db.release_quarantine_item(item_id)
    return jsonify(db.quarantine_row_to_dict(db.get_quarantine_item(item_id)))


# ---------------------------------------------------------------- demo/admin

@bp.post("/admin/rogue-edit/<policy_id>")
def rogue_edit(policy_id):
    """Demo-only hook: mutates `action` directly, WITHOUT re-signing —
    simulating a compromised process with raw database access, so the
    tamper-detection path in evaluate() has something to actually catch.
    Disabled outside DEBUG so it can never ship live."""
    if not current_app.debug:
        return jsonify({"error": "not_found"}), 404

    row = db.get_policy(policy_id)
    if row is None:
        return jsonify({"error": f"no such policy: {policy_id}"}), 404

    body = request.get_json(silent=True) or {}
    new_action = body.get("action")
    if new_action not in ("allow", "deny", "quarantine", "capture"):
        return jsonify({"error": "action must be one of allow, deny, quarantine, capture"}), 400

    db.force_set_action(policy_id, new_action)  # signature left stale on purpose
    updated = db.policy_row_to_dict(db.get_policy(policy_id))
    return jsonify({"warning": "rogue edit applied — signature not recomputed", **updated})


@bp.post("/admin/corrupt-block/<int:idx>")
def corrupt_block(idx):
    """Demo-only hook: rewrites a stored audit block's explanation
    in place WITHOUT recomputing its hash — there is deliberately no
    legitimate API for this. It exists so the console can demonstrate
    that /audit-chain/verify actually catches a rewritten record
    against the real chain, not just a client-side illustration of the
    idea. Disabled outside DEBUG so it can never ship live."""
    if not current_app.debug:
        return jsonify({"error": "not_found"}), 404

    conn = db.get_db()
    row = conn.execute("SELECT * FROM audit_blocks WHERE idx = ?", (idx,)).fetchone()
    if row is None:
        return jsonify({"error": f"no such block: {idx}"}), 404

    conn.execute(
        "UPDATE audit_blocks SET explanation = 'nothing to see here' WHERE idx = ?", (idx,)
    )
    conn.commit()
    return jsonify({"warning": f"block #{idx} rewritten in place — hash left untouched", "idx": idx})

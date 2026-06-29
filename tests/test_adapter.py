"""Deterministic checks for the Domain Adapter layer.

No framework: `python tests/test_adapter.py`.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from authgate.action import Action, RiskVector
from authgate.adapter import AIToolAdapter, FinanceAdapter, QuantumJobAdapter


# ---------------------------------------------------------------------------
# AIToolAdapter
# ---------------------------------------------------------------------------
def test_ai_normalize_maps_fields() -> None:
    a = AIToolAdapter().normalize(
        {
            "actor": "agent:support-bot",
            "tool": "send_email",
            "arguments": {"to": "x@y.z", "body": "hi"},
            "purpose": "support_reply",
            "data_labels": ["customer_support"],
            "session_id": "s-1",
            "nonce": "n-1",
        }
    )
    assert isinstance(a, Action)
    assert a.actor == "agent:support-bot"
    assert a.tool == "send_email"
    assert a.action_purpose == "support_reply"
    assert a.data_labels == ("customer_support",)
    # arguments -> payload
    assert a.payload["to"] == "x@y.z"
    assert a.payload["body"] == "hi"
    assert a.session_id == "s-1"
    assert a.nonce == "n-1"
    # capability left empty -> ABI derives tool:<tool>
    assert a.capability == "tool:send_email"


def test_ai_normalize_tolerates_missing_optionals() -> None:
    a = AIToolAdapter().normalize({"actor": "a", "tool": "read_file"})
    assert a.session_id == "default"
    assert a.nonce == ""
    assert dict(a.payload) == {}
    assert a.data_labels == ()
    assert a.action_purpose == ""


def test_ai_map_capabilities_destructive() -> None:
    ad = AIToolAdapter()
    caps = ad.map_capabilities(ad.normalize({"actor": "a", "tool": "delete_record"}))
    assert caps[0] == "tool:delete_record"
    assert "effect:destructive" in caps


def test_ai_map_capabilities_network() -> None:
    ad = AIToolAdapter()
    caps = ad.map_capabilities(ad.normalize({"actor": "a", "tool": "send_email"}))
    assert "effect:network" in caps


def test_ai_map_capabilities_readonly_has_only_tool_cap() -> None:
    ad = AIToolAdapter()
    caps = ad.map_capabilities(ad.normalize({"actor": "a", "tool": "read_file"}))
    assert caps == ("tool:read_file",)


def test_ai_risk_readonly_more_reversible_than_destructive() -> None:
    ad = AIToolAdapter()
    read = ad.risk_profile(ad.normalize({"actor": "a", "tool": "read_file"}))
    delete = ad.risk_profile(ad.normalize({"actor": "a", "tool": "delete_record"}))
    assert read.reversibility > delete.reversibility
    assert read.blast_radius < delete.blast_radius


def test_ai_risk_sensitivity_from_labels() -> None:
    ad = AIToolAdapter()
    low = ad.risk_profile(
        ad.normalize({"actor": "a", "tool": "read_file", "data_labels": ["public"]})
    )
    high = ad.risk_profile(
        ad.normalize({"actor": "a", "tool": "read_file", "data_labels": ["customer_ssn"]})
    )
    assert high.sensitivity > low.sensitivity


def test_ai_denormalize_wraps_result_and_error() -> None:
    ad = AIToolAdapter()
    ok = ad.denormalize({"sent": True})
    assert ok == {"ok": True, "result": {"sent": True}}
    err = ad.denormalize(ValueError("boom"))
    assert err["ok"] is False
    assert err["error"]["type"] == "ValueError"
    assert err["error"]["message"] == "boom"


# ---------------------------------------------------------------------------
# FinanceAdapter
# ---------------------------------------------------------------------------
def test_finance_normalize_keeps_amount_numeric() -> None:
    a = FinanceAdapter().normalize(
        {
            "actor": "treasury-bot",
            "operation": "transfer",
            "amount": 2500,
            "currency": "USD",
            "account_from": "acct:1",
            "account_to": "acct:2",
            "purpose": "vendor_payment",
        }
    )
    assert a.tool == "transfer"
    assert a.action_purpose == "vendor_payment"
    # amount MUST stay numeric so the budget layer can sum it.
    assert a.payload["amount"] == 2500
    assert isinstance(a.payload["amount"], (int, float))
    assert a.payload["currency"] == "USD"
    assert a.payload["account_from"] == "acct:1"
    assert a.payload["account_to"] == "acct:2"


def test_finance_normalize_tolerates_missing_optionals() -> None:
    a = FinanceAdapter().normalize({"actor": "a", "operation": "transfer"})
    assert a.session_id == "default"
    assert a.nonce == ""
    assert a.payload["amount"] == 0


def test_finance_map_capabilities_financial() -> None:
    ad = FinanceAdapter()
    caps = ad.map_capabilities(ad.normalize({"actor": "a", "operation": "transfer"}))
    assert caps[0] == "tool:transfer"
    assert "effect:financial" in caps


def test_finance_risk_low_reversibility() -> None:
    ad = FinanceAdapter()
    rv = ad.risk_profile(
        ad.normalize({"actor": "a", "operation": "transfer", "amount": 500})
    )
    assert rv.reversibility <= 0.15  # money sent ~ irreversible


def test_finance_blast_scales_with_amount() -> None:
    ad = FinanceAdapter()
    small = ad.risk_profile(
        ad.normalize({"actor": "a", "operation": "transfer", "amount": 50})
    )
    big = ad.risk_profile(
        ad.normalize({"actor": "a", "operation": "transfer", "amount": 5_000_000})
    )
    assert big.blast_radius > small.blast_radius
    assert big.blast_radius <= 1.0  # capped


def test_finance_less_reversible_than_ai_read() -> None:
    # A transfer is less reversible than a read — cross-domain ordering sanity.
    transfer = FinanceAdapter().risk_profile(
        FinanceAdapter().normalize({"actor": "a", "operation": "transfer", "amount": 10})
    )
    read = AIToolAdapter().risk_profile(
        AIToolAdapter().normalize({"actor": "a", "tool": "read_file"})
    )
    assert transfer.reversibility < read.reversibility


def test_finance_denormalize_wraps() -> None:
    ad = FinanceAdapter()
    assert ad.denormalize({"settled": True}) == {"ok": True, "result": {"settled": True}}
    err = ad.denormalize(RuntimeError("rejected"))
    assert err["ok"] is False
    assert err["error"]["type"] == "RuntimeError"


# ---------------------------------------------------------------------------
# QuantumJobAdapter
# ---------------------------------------------------------------------------
def test_quantum_normalize_maps_fields() -> None:
    a = QuantumJobAdapter().normalize(
        {
            "actor": "researcher:lab-7",
            "job": "submit_circuit",
            "backend": "ibmq_kolkata",
            "shots": 4096,
            "circuit_id": "qc:abc",
            "purpose": "vqe_experiment",
        }
    )
    assert a.tool == "submit_circuit"
    assert a.action_purpose == "vqe_experiment"
    assert a.payload["backend"] == "ibmq_kolkata"
    assert a.payload["shots"] == 4096
    assert a.payload["circuit_id"] == "qc:abc"
    assert a.capability == "tool:submit_circuit"


def test_quantum_normalize_tolerates_missing_optionals() -> None:
    a = QuantumJobAdapter().normalize({"actor": "a", "job": "submit_circuit"})
    assert a.session_id == "default"
    assert a.nonce == ""
    assert a.payload["shots"] == 0


def test_quantum_map_capabilities_effect() -> None:
    ad = QuantumJobAdapter()
    caps = ad.map_capabilities(ad.normalize({"actor": "a", "job": "submit_circuit"}))
    assert caps[0] == "tool:submit_circuit"
    assert "effect:quantum_job" in caps


def test_quantum_submit_more_reversible_than_calibrate() -> None:
    ad = QuantumJobAdapter()
    submit = ad.risk_profile(ad.normalize({"actor": "a", "job": "submit_circuit"}))
    calibrate = ad.risk_profile(ad.normalize({"actor": "a", "job": "calibrate_qubit"}))
    reset = ad.risk_profile(ad.normalize({"actor": "a", "job": "reset_device"}))
    assert submit.reversibility > calibrate.reversibility
    assert submit.reversibility > reset.reversibility


def test_quantum_denormalize_wraps() -> None:
    ad = QuantumJobAdapter()
    assert ad.denormalize({"job_id": "j1"}) == {"ok": True, "result": {"job_id": "j1"}}
    err = ad.denormalize(TimeoutError("queue full"))
    assert err["ok"] is False
    assert err["error"]["type"] == "TimeoutError"


# ---------------------------------------------------------------------------
# Cross-cutting: RiskVector validity + protocol conformance
# ---------------------------------------------------------------------------
def test_all_risk_profiles_in_range() -> None:
    cases = [
        (AIToolAdapter(), {"actor": "a", "tool": "delete_record", "data_labels": ["pii"]}),
        (FinanceAdapter(), {"actor": "a", "operation": "transfer", "amount": 9_999_999}),
        (QuantumJobAdapter(), {"actor": "a", "job": "calibrate_qubit"}),
    ]
    for ad, raw in cases:
        rv = ad.risk_profile(ad.normalize(raw))
        assert isinstance(rv, RiskVector)
        for v in (rv.reversibility, rv.blast_radius, rv.sensitivity):
            assert 0.0 <= v <= 1.0


def test_adapter_names() -> None:
    assert AIToolAdapter().name == "ai"
    assert FinanceAdapter().name == "finance"
    assert QuantumJobAdapter().name == "quantum"


def test_protocol_conformance() -> None:
    from authgate.action import DomainAdapter

    for ad in (AIToolAdapter(), FinanceAdapter(), QuantumJobAdapter()):
        assert isinstance(ad, DomainAdapter)


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
    print(f"\n{'all passed' if not failures else f'{failures} failed'}")
    sys.exit(1 if failures else 0)

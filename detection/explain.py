"""Explanations generator with structured plain-English text and guardrails."""

from typing import Dict, List, Tuple
from detection.rules.base import RawFinding


def fmt_inr(amount: float) -> str:
    """Format rupee amount with Indian currency symbol and 2 decimals."""
    return f"₹{amount:,.2f}"


def generate_explanation(finding: RawFinding) -> Tuple[str, str, List[str], List[str]]:
    """Generate (explanation, limitations, alternative_explanations, would_clear_if) for an alert.

    Enforces:
    - Never uses 'fraud' as a conclusion.
    - Plain English with numbers from evidence.
    - Limitations + 'This alone does not prove misuse.'
    - At least 2 alternative explanations.
    - At least 2 would_clear_if items.
    """
    rule_id = finding.rule_id
    ev = finding.evidence
    acc_id = finding.account_ids[0] if finding.account_ids else "Account"

    if rule_id == "RAPID_ONWARD_TRANSFER":
        received = fmt_inr(ev.get("received_inr", 0.0))
        forwarded = fmt_inr(ev.get("forwarded_inr", 0.0))
        pct = ev.get("forwarded_pct", 0.0)
        gap = ev.get("gap_minutes", 0.0)
        receivers_cnt = len(ev.get("outbound_receivers", []))

        explanation = (
            f"Account {acc_id} received {received} and forwarded {forwarded} ({pct:.1f}%) to "
            f"{receivers_cnt} downstream counterparty within {gap:.1f} minutes of receipt. "
            f"This rapid pass-through pattern is consistent with mule layering and warrants review."
        )
        limitations = (
            "Detection is based strictly on transaction timestamps and amounts without account balance context. "
            "This alone does not prove misuse."
        )
        alternatives = [
            "Payment immediately forwarded to a relative, agent, or commercial supplier.",
            "A business account settling an overdue invoice shortly after receiving customer funds.",
            "Shared-cost settlement between personal acquaintances.",
        ]
        would_clear = [
            "The outbound receiver is verified as a legitimate recurring payee or business partner.",
            "The inbound sender and recipient provide evidence of a bona fide commercial relationship.",
            "The forwarded funds constitute an ordinary business cash-flow transit.",
        ]

    elif rule_id == "MULTI_SOURCE_FAN_IN":
        senders = ev.get("distinct_senders", 0)
        first_time = ev.get("first_time_senders", 0)
        share = ev.get("first_time_share", 0.0) * 100
        win = ev.get("window_minutes", 0.0)
        total = fmt_inr(ev.get("total_received_inr", 0.0))

        explanation = (
            f"Account {acc_id} received {total} from {senders} distinct senders within {win:.0f} minutes, "
            f"with {first_time} ({share:.1f}%) being first-time payers. "
            f"This concentrated fan-in pattern may indicate victim fund collection and warrants review."
        )
        limitations = (
            "Evaluation cannot distinguish between retail merchant sales and suspicious collections. "
            "This alone does not prove misuse."
        )
        alternatives = [
            "A newly launched retail stall, small business, or promotional flash sale.",
            "Crowdfunding campaign, social event fee collection, or group gifting.",
            "Community or charity donation collection.",
        ]
        would_clear = [
            "Account holder is registered as a verified retail or institutional merchant.",
            "Transactions include clear payment references matching legitimate commercial invoices.",
            "Payer cohort shows genuine dispersed retail customer behavior.",
        ]

    elif rule_id == "FAN_OUT_SPLITTING":
        received = fmt_inr(ev.get("received_inr", 0.0))
        out_cnt = ev.get("outgoing_count", 0)
        out_total = fmt_inr(ev.get("outgoing_total_inr", 0.0))
        receivers = ev.get("distinct_receivers", 0)
        win = ev.get("window_minutes", 0.0)
        spread = ev.get("amount_spread_pct", 0.0)

        explanation = (
            f"Account {acc_id} received {received} and dispersed {out_total} across {out_cnt} transfers "
            f"to {receivers} distinct accounts within {win:.0f} minutes with a tight amount spread ({spread:.1f}%). "
            f"This structured fan-out pattern is consistent with automated disbursement and warrants review."
        )
        limitations = (
            "Transaction analysis reflects temporal disbursement structure without payer-payee relationship context. "
            "This alone does not prove misuse."
        )
        alternatives = [
            "Group travel or event expense reimbursement to multiple participants.",
            "Informal small business payroll or contractor fee disbursement.",
        ]
        would_clear = [
            "Beneficiaries have documented employment or vendor contracts with the account holder.",
            "Amounts correspond to pre-agreed bill splitting or contractual invoices.",
        ]

    elif rule_id == "TRANSACTION_CYCLE":
        length = ev.get("cycle_length", 0)
        span = ev.get("total_span_minutes", 0.0)
        similarity = ev.get("amount_similarity_pct", 0.0)
        ordered_accs = " -> ".join(ev.get("cycle_accounts", []))

        explanation = (
            f"A closed circular money flow of length {length} was observed ({ordered_accs}) within {span:.1f} minutes, "
            f"with high amount consistency ({similarity:.1f}%). "
            f"This circular routing pattern forms a closed transaction loop across multiple counterparties and warrants review."
        )
        limitations = (
            "Cycle search identifies topological flow loops regardless of underlying intent. "
            "This alone does not prove misuse."
        )
        alternatives = [
            "Sequential debts between mutual acquaintances settling up.",
            "Accidental transfer followed by a refund and re-payment sequence.",
        ]
        would_clear = [
            "Participants demonstrate independent commercial justification for each transfer leg.",
            "The transfers occurred as independent, unrelated personal debts.",
        ]

    elif rule_id == "COMPLAINT_CONVERGENCE":
        comp_cnt = ev.get("complaints_converging", 0)
        traced_tot = fmt_inr(ev.get("traced_total_inr", 0.0))
        max_hops = ev.get("max_hops", 0)
        avg_hops = ev.get("avg_hops", float(max_hops))

        explanation = (
            f"Account {acc_id} received traced funds totaling {traced_tot} originating from {comp_cnt} separate "
            f"user reports within {avg_hops:.1f} average hops. "
            f"This multi-report convergence pattern warrants review."
        )
        limitations = (
            "Proportional tracing assumes fungible flow without direct ledger reconciliation. "
            "This alone does not prove misuse."
        )
        alternatives = [
            "High-volume legitimate merchant receiving payments via third-party gateways with dispute claims.",
            "Accidental payments sent to a public utility or shared municipal service account.",
        ]
        would_clear = [
            "The underlying user reports are dismissed or classified as delivery disputes.",
            "The converging entity is verified as an authorized aggregator or regulated payment processor.",
        ]

    elif rule_id == "NEW_ACCOUNT_BURST":
        age = ev.get("account_age_days", 0)
        txns_day = ev.get("transactions_in_day", 0)
        median_txns = ev.get("typical_daily_transactions", 0.0)
        day = ev.get("day", "")
        dormant = ev.get("dormant_days_before", 0)

        dormant_txt = f" following {dormant} days of dormancy" if dormant else ""
        explanation = (
            f"Account {acc_id} (age {age} days) conducted {txns_day} transactions on {day}{dormant_txt}, "
            f"significantly exceeding the dataset baseline of {median_txns:.1f} daily transactions. "
            f"This sudden activation pattern warrants review."
        )
        limitations = (
            "Account age metrics do not capture off-platform business incubation or pre-existing customer bases. "
            "This alone does not prove misuse."
        )
        alternatives = [
            "Legitimate new business launch or promotional marketing campaign.",
            "Festive or event-driven surge in personal gifting.",
        ]
        would_clear = [
            "The account holder provides business registration documentation matching the burst date.",
            "Transaction frequency remains steady and regular over subsequent operating weeks.",
        ]

    elif rule_id == "COLLECT_REQUEST_ABUSE":
        reqs = ev.get("collect_requests", 0)
        payers = ev.get("distinct_payers", 0)
        win = ev.get("window_minutes", 0.0)
        share = ev.get("collect_share_pct", 0.0)

        explanation = (
            f"Account {acc_id} initiated {reqs} collect requests to {payers} distinct counterparties "
            f"within {win:.0f} minutes, representing {share:.1f}% of its inbound volume. "
            f"This aggressive pull-request pattern may indicate collect spamming or deception and warrants review."
        )
        limitations = (
            "Collect request logging does not disclose specific user consent dialogs or dispute logs. "
            "This alone does not prove misuse."
        )
        alternatives = [
            "A registered biller, utility, or subscription service collecting monthly fees.",
            "A tournament or event organizer sending dues requests to enrolled members.",
        ]
        would_clear = [
            "The counterparties are documented subscribers or members who consented to collect requests.",
            "The account operates under an approved B2B payment mandate.",
        ]

    elif rule_id == "SHARED_DEVICE":
        dev_id = ev.get("device_id", "")
        acc_cnt = len(ev.get("accounts_on_device", []))

        explanation = (
            f"Device {dev_id} is associated with {acc_cnt} distinct accounts. "
            f"This shared hardware association provides operational context and warrants review."
        )
        limitations = (
            "Shared devices are common in households and small retail setups and do not indicate misconduct on their own. "
            "This alone does not prove misuse."
        )
        alternatives = [
            "Family members sharing a single household smartphone or tablet.",
            "A retail store terminal or kiosk used by several authorized cashiers or family business members.",
        ]
        would_clear = [
            "Account holders provide proof of shared household address or common business ownership.",
            "Device usage occurs sequentially within an authorized shared workplace environment.",
        ]

    else:
        explanation = f"Account {acc_id} exhibited transactional patterns consistent with {rule_id} and warrants review."
        limitations = "Detection is heuristic and rule-based. This alone does not prove misuse."
        alternatives = ["Legitimate commercial transfer activity.", "Unusual personal financial settlement."]
        would_clear = ["Counterparty verification.", "Supporting business documentation."]

    return explanation, limitations, alternatives, would_clear

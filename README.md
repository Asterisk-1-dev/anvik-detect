# RingScope: Rulebook Fraud-Pattern Detection Engine

A deterministic, rule-based, and fully explainable detection engine designed for the **RingScope** UPI fraud ring graph investigator.

---

## 1. Overview & Core Principles

- **Investigator-Centric:** The engine identifies suspicious relational and temporal transaction patterns, provides exact supporting transaction IDs, mathematical breakdowns, and alternative explanations, leaving the final judgment to human investigators.
- **Never Declares "Fraud":** Alerts consistently use language such as *"pattern consistent with"*, *"warrants review"*, or *"may indicate"*. The word *"fraud"* is never emitted as a conclusion. Roles assigned in graphs are investigative hypotheses, not findings of wrongdoing.
- **Strictly Deterministic:** Given identical inputs, configuration, and `--generated-at` timestamp, the engine produces byte-identical JSON outputs.
- **Config-Driven:** All thresholds, windows, and weights are declared in [`config.yaml`](file:///c:/Users/user/Desktop/Anvik detect/config.yaml). No magic numbers are hardcoded in rule implementations.
- **Shared Device Guard:** Shared devices are treated as informational context only (`priority = low`, `informational_only = true`), never as proof of collusion or escalation drivers.

---

## 2. Setup & Installation

Requires **Python 3.11+**.

```bash
# Install dependencies
pip install -e .

# Or install dependencies directly
pip install pandas networkx pydantic pyyaml pytest
```

---

## 3. Running Detection via CLI

```bash
python -m detection.cli \
  --input-dir ./data \
  --config ./config.yaml \
  --out ./alerts.json \
  --dataset-id anvik_demo_v1 \
  --generated-at 2026-10-15T12:00:00Z \
  --graph-mode both
```

### CLI Parameters:
- `--input-dir`: Directory containing `accounts.csv`, `devices.csv`, `transactions.csv`, and optional `complaints.csv`.
- `--config`: Path to `config.yaml` (defaults to `config.yaml`).
- `--out`: Output destination path for `alerts.json`.
- `--dataset-id`: Dataset batch identifier (default: `anvik_demo_v1`).
- `--generated-at`: Fixed ISO 8601 timestamp (e.g., `2026-10-15T12:00:00Z`) to ensure byte-level output determinism.
- `--graph-mode`: Graph generation mode: `none`, `alert`, `ring`, or `both` (default: `both`). When set to `none`, graph generation is bypassed and `linked_txn_ids` is an empty list.

---

## 4. Detection Rules & Parameters Table

| Rule ID | Title | Key Config Parameters & Defaults | Suspicion Formula & Logic |
| :--- | :--- | :--- | :--- |
| `RAPID_ONWARD_TRANSFER` | Rapid onward transfer | `min_inbound_inr: 1000`<br>`max_gap_minutes: 15`<br>`min_forwarded_pct: 80` | Evaluates forwarded percentage ($80\%\to100\%$, `scale_up`) and forwarding gap ($15\text{m}\to0\text{m}$, `scale_down`). $\text{suspicion} = 0.5 \times s_{\text{pct}} + 0.5 \times s_{\text{gap}}$. Suppresses refunds to sender & recurring counterparties ($\ge 2$ prior txns). |
| `MULTI_SOURCE_FAN_IN` | Multi-source fan-in | `window_minutes: 60`<br>`min_distinct_senders: 8`<br>`min_first_time_sender_share: 0.7`<br>`max_ratio_to_own_history: 3.0` | Evaluates distinct senders ($8\to20$, `scale_up`) and first-time sender ratio ($0.70\to1.00$, `scale_up`). Weighted average: $0.7 \times s_{\text{count}} + 0.3 \times s_{\text{strangers}}$. Suppressed if sender rate $\le 3\times$ own baseline or within first 7 days (warmup). |
| `FAN_OUT_SPLITTING` | Fan-out splitting | `window_minutes: 30`<br>`min_inbound_inr: 2000`<br>`min_outgoing_count: 3`<br>`min_distinct_receivers: 3`<br>`min_forwarded_pct: 80`<br>`max_amount_spread_pct: 25` | Evaluates forwarded % ($80\%\to100\%$, `scale_up`), amount spread ($25\%\to0\%$, `scale_down`), and outgoing count ($3\to8$, `scale_up`). Weighted average: $0.4 \times s_{\text{pct}} + 0.4 \times s_{\text{spread}} + 0.2 \times s_{\text{count}}$. |
| `TRANSACTION_CYCLE` | Transaction cycle | `min_length: 3`<br>`max_length: 5`<br>`max_span_hours: 6`<br>`min_amount_similarity: 0.8`<br>`min_amount_inr: 500`<br>`max_cycles_reported: 200` | Prunes graph with strongly connected components (SCC), runs bounded DFS, validates strictly time-respecting hop ordering ($t_1 < t_2 < \dots < t_k$) and $\min/\max \ge 0.8$. Evaluates hop count ($5\to3$, `scale_down`) and amount similarity ($0.80\to1.00$, `scale_up`). $\text{suspicion} = 0.5 \times s_{\text{hops}} + 0.5 \times s_{\text{sim}}$. |
| `COMPLAINT_CONVERGENCE` | Complaint convergence | `max_hops: 3`<br>`trace_window_hours: 24`<br>`min_converging_complaints: 2`<br>`min_traced_amount_inr: 500`<br>`trace_method: proportional` | Traces fund flows proportionally downstream from reported transactions. Evaluates converging complaint count ($2\to6$, `scale_up`) and average minimum hops ($3.0\to1.0$, `scale_down`). $\text{suspicion} = 0.5 \times s_{\text{count}} + 0.5 \times s_{\text{hops}}$. Never scores below 0.50. |
| `NEW_ACCOUNT_BURST` | New account burst | `max_account_age_days: 45`<br>`min_txns_in_day: 10`<br>`burst_multiplier_vs_median: 4`<br>`dormant_days: 14` | Compares daily txns against active account median daily volume ($\ge 4\times$). Suspicion scales with txns in day ($10\to30$, `scale_up`) with a $+0.20$ bonus if preceded by $\ge 14$ dormant days (clamped to 1.0). Zero-base start: accounts with no history are treated as active unless age exceeds dormant threshold. |
| `COLLECT_REQUEST_ABUSE` | Collect request abuse | `window_minutes: 120`<br>`min_collect_txns: 5`<br>`min_distinct_payers: 4`<br>`min_collect_share_of_inbound: 0.6`<br>`include_failed_in_attempts: true` | Flags receiver initiating excessive collect requests to distinct payers. Evaluates collect requests ($5\to15$, `scale_up`) and distinct payers ($4\to10$, `scale_up`). $\text{suspicion} = 0.5 \times s_{\text{count}} + 0.5 \times s_{\text{payers}}$. Failed collect share recorded in evidence only. |
| `SHARED_DEVICE` | Shared device | `min_accounts: 3`<br>`informational_only: true` | Informational context alerts for devices linked to $\ge 3$ accounts. Bypasses formula with a flat score of `0.20` and `priority: low`. Excluded from escalation. |

---

## 5. Documented Assumptions

1. **Timestamps & Timezones:** Input timestamps are assumed UTC by default (`general.assume_timezone: UTC`). All emitted timestamps use standard ISO 8601 UTC format ending in `Z`.
2. **UPI COLLECT Semantics:** In UPI collect requests, money flows from `sender_vpa` to `receiver_vpa`. The **initiator** of the collect request is the **receiver** (the payee asking for payment). This is explicitly configurable via `general.collect_initiator: receiver`.
3. **Money Movement:** Only `SUCCESS` transactions represent actual money movement and feed graph edges and movement rules. `FAILED` transactions are exclusively utilized to measure spam/abuse in `COLLECT_REQUEST_ABUSE`.
4. **Currency:** Amounts are floats in Indian Rupees (INR) and are formatted in plain-text explanations using `₹` (e.g. `₹10,000.00`).

---

## 6. Scoring v2.0, Suspicion, Priority & Escalation

Scoring in RingScope v2.0 is entirely config-driven, bounded, and explainable without complex ML models.

### 6.1 The Core Idea: Intuitive Slider Helper
Every observable signal in a detected pattern (like forwarding percentage, sender count, or transfer time gap) is mapped onto a simple $0.0$ to $1.0$ slider:
- **`scale_up(value, low, high)`**: Used when higher numbers are more suspicious. A value at `low` gets $0.0$ (just suspicious enough to trigger), a value at `high` gets $1.0$ (extreme suspicion), values in between scale linearly, and values outside are clamped to $[0.0, 1.0]$.
- **`scale_down(value, cutoff, best)`**: Used when lower numbers are more suspicious (e.g., shorter delays or fewer hops). A value at `cutoff` gets $0.0$, a value at `best` gets $1.0$, scaling linearly in between.

### 6.2 Suspicion Table

| Rule ID | Signals Used | Sliders & Weights |
| :--- | :--- | :--- |
| `RAPID_ONWARD_TRANSFER` | Forwarded % and gap minutes | `forwarded_pct`: 80% to 100% (`scale_up`)<br>`gap_minutes`: 15m to 0m (`scale_down`)<br>$\text{suspicion} = 0.5 \times s_{\text{pct}} + 0.5 \times s_{\text{gap}}$ |
| `MULTI_SOURCE_FAN_IN` | Sender count and first-time sender ratio | `distinct_senders`: 8 to 20 (`scale_up`)<br>`first_time_share`: 0.70 to 1.00 (`scale_up`)<br>$\text{suspicion} = 0.7 \times s_{\text{count}} + 0.3 \times s_{\text{strangers}}$ |
| `FAN_OUT_SPLITTING` | Forwarded %, amount spread %, outgoing count | `forwarded_pct`: 80% to 100% (`scale_up`)<br>`amount_spread_pct`: 25% to 0% (`scale_down`)<br>`outgoing_count`: 3 to 8 (`scale_up`)<br>$\text{suspicion} = 0.4 \times s_{\text{pct}} + 0.4 \times s_{\text{spread}} + 0.2 \times s_{\text{count}}$ |
| `TRANSACTION_CYCLE` | Hop count and amount similarity | `hop_count`: 5 to 3 (`scale_down`)<br>`amount_similarity`: 0.80 to 1.00 (`scale_up`)<br>$\text{suspicion} = 0.5 \times s_{\text{hops}} + 0.5 \times s_{\text{sim}}$ |
| `COMPLAINT_CONVERGENCE` | Complaint count and average hops | `complaint_count`: 2 to 6 (`scale_up`)<br>`avg_hops`: 3.0 to 1.0 (`scale_down`)<br>$\text{suspicion} = 0.5 \times s_{\text{count}} + 0.5 \times s_{\text{hops}}$ |
| `NEW_ACCOUNT_BURST` | Transaction count in burst day and dormancy | `txns_in_day`: 10 to 30 (`scale_up`)<br>Preceding dormancy $\ge 14$ days adds $+0.20$ bonus<br>$\text{suspicion} = \text{clamp}(s_{\text{count}} + \text{dormant\_bonus}, 0.0, 1.0)$ |
| `COLLECT_REQUEST_ABUSE` | Collect request count and distinct payers | `collect_count`: 5 to 15 (`scale_up`)<br>`distinct_payers`: 4 to 10 (`scale_up`)<br>$\text{suspicion} = 0.5 \times s_{\text{count}} + 0.5 \times s_{\text{payers}}$ |
| `SHARED_DEVICE` | Shared device links | Bypasses sliders: flat score $0.20$, context only. |

### 6.3 Score Formula and Exceptions
For all behavioral rules, base score is calculated as:
$$\text{base\_score} = \text{rule\_weight} \times \left( \text{base\_offset} + (1.0 - \text{base\_offset}) \times \text{suspicion} \right)$$
where $\text{base\_offset} = 0.40$. The final score incorporates additive escalation bonuses:
$$\text{final\_score} = \text{clamp}(\text{base\_score} + \text{family\_bonus} + \text{complaint\_bonus}, 0.0, 1.0)$$

**Exceptions:**
1. **`SHARED_DEVICE`:** Always scores a flat $0.20$. It never uses the formula, never escalates, and never contributes to family escalation on other alerts.
2. **`COMPLAINT_CONVERGENCE`:** Enforces a minimum score floor of $0.50$ ($\text{final\_score} = \max(0.50, \text{computed\_score})$). It never receives the complaint-link bonus (since the alert itself is grounded in complaints).

### 6.4 Priority Derivation Table
Priorities are strictly derived from the rounded final score:
| Final Score Range | Priority | Meaning |
| :--- | :--- | :--- |
| $\text{score} \ge 0.75$ | **High** | Critical pattern warranting immediate review. |
| $0.45 \le \text{score} < 0.75$ | **Medium** | Moderately suspicious pattern warranting routine investigation. |
| $\text{score} < 0.45$ | **Low** | Weak or informational signal (or isolated lower-weight pattern). |

### 6.5 Rule-Family Escalation
Rather than counting raw alert counts or rule IDs, RingScope v2.0 groups rules into **functional behavioral families**:
- `PASS_THROUGH`: `RAPID_ONWARD_TRANSFER`, `FAN_OUT_SPLITTING`
- `INFLOW`: `MULTI_SOURCE_FAN_IN`, `COLLECT_REQUEST_ABUSE`
- `LOOP`: `TRANSACTION_CYCLE`
- `COMPLAINT`: `COMPLAINT_CONVERGENCE`
- `ACCOUNT_BEHAVIOR`: `NEW_ACCOUNT_BURST`
- `CONTEXT`: `SHARED_DEVICE` *(excluded from escalation)*

**Why Rule Families?** Multiple detections within the same family (e.g. `RAPID_ONWARD_TRANSFER` and `FAN_OUT_SPLITTING` triggered on the same splitting hop) measure the exact same physical movement of funds. Escalation should reward **orthogonal corroboration**—for example, seeing both an influx of funds from stranger accounts (`INFLOW`) and instantaneous onward forwarding (`PASS_THROUGH`) on the same focal account.
- **Family Bonus:** $+0.10$ for each additional distinct non-context family present on the alert's focal account(s), capped at $+0.30$.
- **Complaint Link Bonus:** $+0.10$ if a focal account lies on a confirmed complaint trail (not applied to `COMPLAINT_CONVERGENCE` alerts).

### 6.6 "Can This Rule Reach High on Its Own?"

| Rule ID | Weight | Max Standalone Score | Can Reach High Alone? | What It Takes to Reach High Alone |
| :--- | :--- | :--- | :--- | :--- |
| `RAPID_ONWARD_TRANSFER` | 1.0 | 1.00 | **Yes** | 100% forwarded + 0 min gap (suspicion $\ge 0.583$) |
| `MULTI_SOURCE_FAN_IN` | 1.0 | 1.00 | **Yes** | 20+ senders + 100% first-timers (suspicion $\ge 0.583$) |
| `COMPLAINT_CONVERGENCE` | 1.0 | 1.00 | **Yes** | 6+ complaints + 1 hop (suspicion $\ge 0.583$) |
| `FAN_OUT_SPLITTING` | 0.8 | 0.80 | **Yes** | 100% forwarded + 0% spread + 8+ receivers (needs suspicion $\ge 0.895$) |
| `COLLECT_REQUEST_ABUSE` | 0.8 | 0.80 | **Yes** | 15+ requests + 10+ payers (needs suspicion $\ge 0.895$) |
| `TRANSACTION_CYCLE` | 0.8 | 0.80 | **Yes** | 3 hops + 100% similarity (needs suspicion $\ge 0.895$) |
| `NEW_ACCOUNT_BURST` | 0.6 | 0.60 | **No** | Needs escalation from another family to reach High (max standalone is 0.60) |
| `SHARED_DEVICE` | N/A | 0.20 | **No** | Flat score 0.20, always Low priority |

### 6.7 Worked Scoring Examples

#### Example 1: Borderline Rapid Onward Transfer (Standalone)
- **Inputs:** 80% forwarded (the detection threshold), 15 min gap.
- **Sliders:**
  - $s_{\text{pct}} = \text{scale\_up}(80, 80, 100) = 0.0$
  - $s_{\text{gap}} = \text{scale\_down}(15, 15, 0) = 0.0$
  - $\text{suspicion} = 0.5 \times 0.0 + 0.5 \times 0.0 = 0.00$
- **Base Score:** $1.0 \times (0.40 + 0.60 \times 0.00) = 0.40$
- **Escalation:** No other families on focal account ($+0.00$).
- **Final Score:** $0.40 \implies$ **Priority: Low** (or borderline Medium threshold).

#### Example 2: Strong Rapid Onward Transfer (Standalone)
- **Inputs:** 90% forwarded, 5 min gap.
- **Sliders:**
  - $s_{\text{pct}} = \text{scale\_up}(90, 80, 100) = (90 - 80) / 20 = 0.50$
  - $s_{\text{gap}} = \text{scale\_down}(5, 15, 0) = (15 - 5) / 15 = 0.6667$
  - $\text{suspicion} = 0.5 \times 0.50 + 0.5 \times 0.6667 = 0.5833$
- **Base Score:** $1.0 \times (0.40 + 0.60 \times 0.5833) = 0.40 + 0.35 = 0.75$
- **Escalation:** No other families ($+0.00$).
- **Final Score:** $0.75 \implies$ **Priority: High**.

#### Example 3: Low-Weight Rule with Multi-Family Escalation (New Account Burst)
- **Inputs:** 10 transactions in burst day (baseline), account previously active ($\text{dormant\_bonus} = 0.0$).
- **Sliders:**
  - $s_{\text{count}} = \text{scale\_up}(10, 10, 30) = 0.0$
  - $\text{suspicion} = 0.00$
- **Base Score:** $0.6 \times (0.40 + 0.60 \times 0.00) = 0.24$
- **Escalation Scenarios:**
  - *Standalone:* Final score $0.24 \implies$ **Low**.
  - *Corroborated by `PASS_THROUGH` and `INFLOW` families:* $+0.20$ family bonus $\to$ score $0.44 \implies$ **Low** (at borderline of Medium).
  - *Corroborated by 3 distinct families (`PASS_THROUGH`, `INFLOW`, `LOOP`):* $+0.30$ family bonus $\to$ score $0.54 \implies$ **Medium**.

### 6.8 Calibration Note
The slider bounds and weights in RingScope v2.0 are calibrated against synthetic test fixtures and known UPI fraud typologies. In a production deployment:
- **Slider Bounds:** Should be fitted to empirical historical distributions (e.g., the 8-to-20 distinct senders range should map to the 90th-to-99th percentile of peer accounts).
- **Base Offset ($0.40$):** Controls false-alarm volume. Raising it pushes borderline detections into Medium; lowering it retains more alerts in Low.
- **Rule Weights:** Reflect institutional confidence in each pattern as an isolated signal (`RAPID_ONWARD` and `COMPLAINT` are weighted 1.0; `NEW_ACCOUNT_BURST` is weighted 0.6 because benign accounts also experience spikes).
- **Escalation Cap ($0.30$):** Ensures that multi-rule corroboration elevates actionable Medium alerts to High (+0.10 to +0.20 is typically sufficient), while preventing benign or weak events from reaching High on corroboration alone.

---

## 7. Directed Transaction Graph Output & Roles

Every alert and every ring contains a `graph` object representing the directed transaction network. Each alert also carries `linked_txn_ids` listing non-supporting context payment edges.

### 7.1 Graph Role Assignment

| Rule | `origin_account` | `potential_mule` | `receiving_account` | `destination_account` | `linked_account` |
|---|---|---|---|---|---|
| `RAPID_ONWARD_TRANSFER` | Sender of inbound transaction | The account that forwards | - | Receivers of forwarded transactions | Other context accounts |
| `MULTI_SOURCE_FAN_IN` | Distinct senders | The receiving account | - | Downstream receivers (context) | Other context accounts |
| `FAN_OUT_SPLITTING` | Sender of inbound transaction | The account that splits | - | Receivers of split transfers | Other context accounts |
| `TRANSACTION_CYCLE` | Sender of earliest transaction in cycle | - | - | - | All other cycle accounts |
| `COMPLAINT_CONVERGENCE` | Victim account of each complaint | The converging account | Accounts on trails between victim & converging account | Accounts at ends of trails | Other context accounts |
| `NEW_ACCOUNT_BURST` | - | The new account | - | - | Counterparties |
| `COLLECT_REQUEST_ABUSE` | The payers | The requesting account | - | - | Other context accounts |
| `SHARED_DEVICE` | - | - | - | - | All accounts on device |

*Device Roles:* `shared_device` (linked to $\ge 2$ graph accounts) and `origin_device` (device on earliest supporting transaction).  
*Precedence:* `potential_mule` > `origin_account` > `receiving_account` > `destination_account` > `linked_account`.

### 7.2 Graph Configuration Parameters

Configured under the `graph` block in `config.yaml`:
```yaml
graph:
  enabled: true
  include_devices: true
  collect_request_as_node: false
  context_hops: 1
  context_window_hours: 48
  max_context_edges: 25
  max_nodes: 40
  max_ring_edges: 80
  max_ring_nodes: 80
```

---

## 8. Output Schema & JSON Schema Export

Export the formal JSON Schema:
```bash
python -m tools.export_schema
```
This generates [`schema/output.schema.json`](file:///c:/Users/user/Desktop/Anvik detect/schema/output.schema.json).

An end-to-end sample output file with full alert graphs and ring graphs is available at [`examples/sample_output_with_graph.json`](file:///c:/Users/user/Desktop/Anvik detect/examples/sample_output_with_graph.json).

---

## 9. Evaluation Tool (`tools/evaluate.py`)

A standalone validation script (never imported by the detection engine) that computes precision, recall, F1-score, and priority match rates against an expected results JSON:

```bash
python tools/evaluate.py --alerts alerts.json --ground-truth expected_results.json --out-report eval_report.json
```

---

## 10. Known Limitations

- **No True Ledger Balances:** Since bank balances are not present in transaction logs, account retention is approximated from windowed inbound and outbound flows.
- **Synthetic Data Baseline:** Median burst rates and transaction velocities are tuned for synthetic benchmarks and should be recalibrated against real-world bank or PSP baselines.

---

## 11. Running Tests

```bash
python -m pytest -q
```
All 85 tests pass, covering unit rules, slider bounds, score calculation and priority derivation, rule-family escalation, wording guards, graph schema and direction, role assignments and precedence, truncation, device linking, and full determinism.

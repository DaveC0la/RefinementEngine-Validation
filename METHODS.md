# Validation methodology

## Experimental setting

The experiments were conducted on a PC with an AMD Ryzen 7 5825U processor and 16 GB of RAM, running Ubuntu 24.04.4 LTS under WSL2.
The benchmark used Python 3.12.3 and PuLP 3.3.2 with CBC 2.10.3. The Kathará laboratory contains 31 devices and 31 collision domains, including perimeter and internal packet filters, a ModSecurity web application firewall, two Squid egress proxies, enterprise endpoints and alternative modelled paths. Its topology, addressing and baseline security configurations are provided in [`topology/`](topology/).

The refinement inputs combine HSPL prohibition intents, structured CTI and a network/control model. The experiments assess generated enforcement using pre-specified expected outcomes, native configuration inspection and traffic probes. The evaluated physical cases materialise native rules from the Refiner's intermediate artefacts through the laboratory rule-generation workflow.

## RQ1 — Enforcing supported prohibitions

Cases A1–A7 cover source-IP restrictions, a destination-IP/TCP-port conjunction, inbound URL-path and User-Agent filtering at the WAF, and outbound HTTP URL, User-Agent and domain filtering at the proxies. Observations compare target traffic, near matches, unrelated traffic and baseline behavior before enforcement, during enforcement and following withdrawal. Each case includes an HSPL input, a readable reference, native snapshots and a traffic table.

Cases B1–B3 vary the network-context model or available enforcement controls while retaining the prohibition. The B3 case provides the HSPL, a change in management eligibility, independently specified expected locations and recorded native/traffic results. The B1 allocation dataset has four model-level candidates, including an unselected EgressProxy/Squid candidate; physical tests establish enforcement at the selected firewall. 

Cases C1–C3 check rejection of unsupported conditions, inseparable conditions that no eligible single control supports, and controls outside the relevant path, alongside feasible reference cases.

## Allocation benchmark

The allocation comparison includes five inputs from the network-context experiments and three constructed multipath instances. Each input is evaluated with the greedy allocator and a minimum-cardinality ILP reference. The recorded benchmark used PuLP 3.3.2 with CBC, one untimed warm-up and 25 timed repetitions per method and instance. Execution time was measured using `time.perf_counter_ns()`. Table values report the median and the 23rd ordered observation of 25 as the 95th percentile. The figures measure allocation computation, not full policy generation or deployment.

## RQ2 — Actionability-driven adaptation

The lifecycle campaign evaluates S0–S9 against expected ownership, effective-rule changes, native configurations and traffic decisions. Each step retains the complete active owner state. Two independently managed domain IoCs share the same rules at the headquarters and branch proxies, while the source-IP restriction is also shared. Changes to the active IoCs cause rule additions, removals or ownership-only updates. The evaluated sequence records five verified additions and five removals of CTI-informed effective rules, with no additional configuration operations. A separate run tests the reverse order of domain-owner withdrawal.

Native snapshots and traffic tables support the observed enforcement after each relevant change. Additional IP/port target and near-match probes are included under [`RQ2/supporting_runs/ip_port_precision/`](RQ2/supporting_runs/ip_port_precision/).

# PRAXIS Phase 34 Inferential Statistics Summary

## Purpose

Convert PRAXIS collected logs, session-level CSVs, detector outputs, and public-baseline datasets into inferential statistical evidence for dissertation Chapters 3–5.

## Method

The unit of inference is one PRAXIS session. Individual packets are not treated as independent observations.

Continuous outcomes are analyzed using bootstrap confidence intervals, permutation tests, Mann–Whitney U tests, Cohen's d, and Cliff's delta.

Binary success outcomes are analyzed using Wilson confidence intervals and Fisher exact tests.

## Main Phase 17 detector-confidence inference

- baseline_mean=1.000000
- default_c2_p1_mean=0.487000
- delta=-0.513000
- pct_delta=-51.30%
- bootstrap_95ci=[-0.514000,-0.511900]
- permutation_p_two_sided=0.000100
- cohen_d=-185.438443

## Phase 17 PRAXIS-score inference

- metric=praxis_score_phase17
- baseline_mean=0.654073
- default_c2_p1_mean=0.432949
- delta=-0.221124
- bootstrap_95ci=[-0.254584,-0.187908]
- permutation_p_two_sided=0.000100

## Phase 17 compliance inference

- baseline_default_off: success=50/50, success_rate=1.0, wilson_95ci=[0.9286499658256813,1.0]
- camouflaged_c2_p1: success=50/50, success_rate=1.0, wilson_95ci=[0.9286499658256813,1.0]
- default_c2_p1: success=50/50, success_rate=1.0, wilson_95ci=[0.9286499658256813,1.0]

## Phase 21 RQ3 resolver success inference

- decentralized_resolution: success=30/30, success_rate=1.0, wilson_95ci=[0.8864829086095221,1.0]
- dns_blocked: success=0/30, success_rate=0.0, wilson_95ci=[0.0,0.113517091390478]
- standard_dns_lab: success=30/30, success_rate=1.0, wilson_95ci=[0.8864829086095221,1.0]

## Phase 20 holdout-detector inference

- phase20_strict_unseen: baseline=0.959737, default_c2_p1=0.666053, delta=-0.293684, ci=[-0.310496,-0.277289], p=0.000100
- phase20_baseline_known: baseline=0.998023, default_c2_p1=0.663093, delta=-0.334930, ci=[-0.349311,-0.320694], p=0.000100

## Phase 31 public-baseline sensitivity

- cicids2017_mapped: winner=default_c2_p1, default_c2_p1_score_delta_vs_baseline=-0.3011837367032921
- mawi_day1: winner=default_c2_p1, default_c2_p1_score_delta_vs_baseline=-0.2207006421917152
- mawi_day1_day2: winner=default_c2_p1, default_c2_p1_score_delta_vs_baseline=-0.2224510900485888
- mawi_day2: winner=default_c2_p1, default_c2_p1_score_delta_vs_baseline=-0.220495837604953
- mawi_plus_cicids_balanced: winner=default_c2_p1, default_c2_p1_score_delta_vs_baseline=-0.2552804246640713

## Feature-level inference

Top feature-level effects by absolute Cohen's d:
- flow_duration_seconds: delta=-0.954717, cohen_d=-313.323775, BH_adjusted_p=1.766517982597233e-17
- in_payload_bytes: delta=134.480000, cohen_d=26.882398, BH_adjusted_p=8.487871550272424e-20
- packet_count: delta=-15.040000, cohen_d=-10.226662, BH_adjusted_p=1.1325115548072297e-17
- out_packets: delta=-8.240000, cohen_d=-9.457009, BH_adjusted_p=9.183999344711302e-18
- in_packets: delta=-6.800000, cohen_d=-9.295882, BH_adjusted_p=3.896441984601071e-18
- pcap_size_bytes: delta=-1172.280000, cohen_d=-7.786430, BH_adjusted_p=1.766517982597233e-17
- burst_count: delta=-9.240000, cohen_d=-4.040922, BH_adjusted_p=1.6973056311964586e-17
- total_payload_bytes: delta=199.240000, cohen_d=2.753644, BH_adjusted_p=3.768467639493218e-16
- out_payload_bytes: delta=64.760000, cohen_d=0.894077, BH_adjusted_p=1.593358356096792e-05
- len_19: delta=-2.280000, cohen_d=-0.596437, BH_adjusted_p=0.0005022380077065441

## Interpretation

Phase 34 strengthens PRAXIS by adding inferential statistics to the already completed engineering and experimental work.

The results should be interpreted as support for detector-confidence reduction and adaptive configuration selection under the PRAXIS lab threat model.

They should not be interpreted as complete detector bypass, universal detector robustness, real-world censorship evasion, or production blockchain DDNS deployment.


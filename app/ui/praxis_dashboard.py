import sys
sys.path.insert(0, "/opt/praxis/app/lib")

import pandas as pd
import streamlit as st
import praxis_core as core

st.set_page_config(
    page_title="PRAXIS Controller Studio",
    layout="wide",
)

st.title("PRAXIS Adaptive Camouflage Controller Studio")

st.markdown(
    """
This app demonstrates PRAXIS as a measurement-guided configuration-selection service.

It uses completed PRAXIS Cycle 2 evidence to rank configurations by detector confidence,
public-benign distance, overhead, and compliance.
"""
)

summary = core.summary()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Baseline Detector Probability", "1.000")
c2.metric("Best Detector Probability", "0.487")
c3.metric("Detector Delta", "-0.513")
c4.metric("Compliance", "100%")

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "Controller",
    "Research Questions",
    "Robustness",
    "RQ3 Resolver",
    "Claims",
    "Artifacts",
])

with tab1:
    st.header("Adaptive Controller Ranking")

    st.sidebar.header("Controller Weights")
    detector_weight = st.sidebar.slider("Detector probability weight", 0, 100, 45)
    public_weight = st.sidebar.slider("Public-benign distance weight", 0, 100, 35)
    overhead_weight = st.sidebar.slider("Overhead weight", 0, 100, 5)
    compliance_weight = st.sidebar.slider("Compliance penalty weight", 0, 100, 15)

    result = core.controller_ranking(
        detector_weight=detector_weight,
        public_weight=public_weight,
        overhead_weight=overhead_weight,
        compliance_weight=compliance_weight,
    )

    if result["error"]:
        st.error(result["error"])
    else:
        winner = result["winner"]
        st.success(f"Current winner: {winner['config_id']} with adjusted score {winner['adjusted_score']:.6f}")

        df = pd.DataFrame(result["ranking"])
        st.dataframe(df, use_container_width=True)

        plot_df = df.set_index("config_id")[[
            "adjusted_score",
            "mean_detector_proxy_probability",
            "mean_public_robust_log_distance_norm",
            "mean_overhead_norm",
        ]]
        st.bar_chart(plot_df)

    st.subheader("Why this is novel")
    st.markdown(
        """
PRAXIS is not a static proxy setting. It is a controller.

The controller:
1. loads candidate configurations,
2. evaluates detector confidence,
3. compares traffic shape against public benign traffic,
4. accounts for overhead and compliance,
5. ranks candidates under adjustable weights,
6. confirms the selected configuration out of sample.
"""
    )

with tab2:
    st.header("Research Questions and Status")
    rq_df = pd.DataFrame(core.rq_status())
    st.dataframe(rq_df, use_container_width=True)

with tab3:
    st.header("Fresh Detector Robustness")

    p20 = core.phase20_scores()
    if p20.empty:
        st.warning("Phase 20 score file not found.")
    else:
        st.dataframe(p20, use_container_width=True)

        if "mode" in p20.columns and "mean_holdout_proxy_probability" in p20.columns:
            for mode in sorted(p20["mode"].dropna().unique()):
                sub = p20[p20["mode"] == mode].copy().set_index("config_id")
                st.subheader(f"Holdout detector mode: {mode}")
                st.bar_chart(sub[["mean_holdout_proxy_probability"]])

    p20b = core.phase20b_thresholds()
    st.subheader("Threshold validation")
    if p20b.empty:
        st.warning("Phase 20B threshold file not found.")
    else:
        st.dataframe(p20b, use_container_width=True)

with tab4:
    st.header("RQ3 Resolver-Independence Result")

    phase21 = core.phase21_summary()
    if phase21.empty:
        st.warning("Phase 21 catalog not found.")
    else:
        st.dataframe(phase21, use_container_width=True)
        st.bar_chart(phase21.set_index("resolution_mode")[["success_rate"]])

    st.markdown(
        """
Expected and confirmed pattern:

- `standard_dns_lab`: succeeds
- `dns_blocked`: fails
- `decentralized_resolution`: succeeds

Boundary: this confirms controlled resolver independence, not production blockchain DDNS.
"""
    )

with tab5:
    st.header("Claim Boundary")

    st.subheader("Confirmed vs Not Confirmed")
    cb = pd.DataFrame(core.claim_boundary())
    st.dataframe(cb, use_container_width=True)

    st.subheader("Final Claim")
    st.markdown(core.read_text(core.PATHS["final_claim"], fallback="Final claim file not found."))

with tab6:
    st.header("Artifact Status")

    files = pd.DataFrame(core.file_status())
    st.dataframe(files, use_container_width=True)

    if st.button("Export controller JSON"):
        path = core.export_json(core.BASE / "app/exports/praxis_controller_export.json")
        st.success(f"Exported: {path}")

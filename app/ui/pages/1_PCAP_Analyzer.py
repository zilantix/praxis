# PRAXIS portable path bootstrap
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
for _p in [_HERE.parent, *_HERE.parents]:
    _candidate = _p / "app" / "lib"
    if _candidate.exists():
        sys.path.insert(0, str(_candidate))
        break
# End PRAXIS portable path bootstrap

import sys
from pathlib import Path
import shutil
import tempfile


import pandas as pd
import streamlit as st

import praxis_pcap_analyzer as analyzer


st.set_page_config(
    page_title="PRAXIS PCAP Analyzer",
    layout="wide",
)

st.title("PRAXIS PCAP Analyzer")

st.markdown(
    """
Upload a packet capture and compute PRAXIS-compatible traffic-shape features.

This page supports research analysis of a pcap. It does not claim detector evasion unless a detector
probability or detector model is supplied separately.
"""
)

with st.expander("Safety and privacy boundary", expanded=True):
    st.markdown(
        """
- Do not upload pcaps containing sensitive third-party traffic unless you have authorization.
- This app extracts aggregate traffic-shape metadata only.
- Raw pcaps are not needed after analysis and can be deleted automatically.
- Without detector probability, the output is a partial PRAXIS score only.
"""
    )

uploaded = st.file_uploader("Upload .pcap or .pcapng", type=["pcap", "pcapng", "cap"])

col1, col2, col3 = st.columns(3)

with col1:
    client_ip = st.text_input("Client/source IP in pcap", value="")
    session_id = st.text_input("Session ID", value="CUSTOM_SESSION_001")

with col2:
    config_id = st.text_input("Config ID", value="custom_config")
    success = st.selectbox("Session success", options=[1, 0], index=0)

with col3:
    overhead_budget_bytes = st.number_input(
        "Overhead budget bytes",
        min_value=1,
        value=1000000,
        step=10000,
        help="Used to normalize pcap size. Set this to your expected maximum acceptable pcap/session size.",
    )
    delete_raw_pcap = st.checkbox("Delete raw pcap after analysis", value=True)

st.subheader("Public-benign baseline")

default_baseline = analyzer.default_public_baseline()
baseline_mode = st.radio(
    "Baseline source",
    ["Use server default baseline", "Upload baseline CSV"],
    horizontal=True,
)

public_baseline_path = default_baseline
uploaded_baseline = None

if baseline_mode == "Use server default baseline":
    st.code(str(default_baseline))
    if not default_baseline.exists():
        st.warning("Default baseline file does not exist. Upload a public-benign feature CSV instead.")
else:
    uploaded_baseline = st.file_uploader("Upload public-benign baseline CSV", type=["csv"])

st.subheader("Optional detector probability")

use_detector_prob = st.checkbox("I have detector probability for this pcap", value=False)

detector_probability = None
if use_detector_prob:
    detector_probability = st.number_input(
        "Detector proxy probability",
        min_value=0.0,
        max_value=1.0,
        value=0.5,
        step=0.01,
    )

st.subheader("Scoring weights")

w1, w2, w3, w4 = st.columns(4)

with w1:
    detector_weight = st.slider("Detector", 0, 100, 45)

with w2:
    public_weight = st.slider("Public distance", 0, 100, 35)

with w3:
    overhead_weight = st.slider("Overhead", 0, 100, 5)

with w4:
    compliance_weight = st.slider("Compliance", 0, 100, 15)

run = st.button("Analyze pcap", type="primary")

if run:
    if uploaded is None:
        st.error("Upload a pcap first.")
        st.stop()

    if not client_ip.strip():
        st.error("Enter the client/source IP address from the pcap.")
        st.stop()

    upload_dir = analyzer.make_upload_dir()

    pcap_path = upload_dir / uploaded.name
    pcap_path.write_bytes(uploaded.getbuffer())

    if uploaded_baseline is not None:
        public_baseline_path = upload_dir / uploaded_baseline.name
        public_baseline_path.write_bytes(uploaded_baseline.getbuffer())

    try:
        result = analyzer.analyze_pcap(
            pcap_path=pcap_path,
            client_ip=client_ip.strip(),
            session_id=session_id.strip(),
            config_id=config_id.strip(),
            success=int(success),
            public_baseline_path=Path(public_baseline_path),
            detector_probability=detector_probability if use_detector_prob else None,
            overhead_budget_bytes=int(overhead_budget_bytes),
            detector_weight=float(detector_weight),
            public_weight=float(public_weight),
            overhead_weight=float(overhead_weight),
            compliance_weight=float(compliance_weight),
        )

        outputs = analyzer.write_analysis_outputs(result, upload_dir / "outputs")

        summary = result["summary"]
        scored_df = result["scored_df"]
        features_df = result["features_df"]

        st.success("Analysis complete.")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Packets", summary["packet_count"])
        m2.metric("Payload bytes", summary["total_payload_bytes"])
        m3.metric("Public distance norm", f"{summary['public_robust_log_distance_norm']:.6f}")
        m4.metric("PRAXIS score", f"{summary['praxis_score']:.6f}")

        if summary["score_type"] == "partial_score_no_detector":
            st.warning(
                "Partial score only: no detector probability was supplied. "
                "Do not claim detector-confidence reduction from this run."
            )
        else:
            st.info("Full score includes the detector probability supplied by the user.")

        st.subheader("Summary")
        st.json(summary)

        st.subheader("Scored session row")
        st.dataframe(scored_df, use_container_width=True)

        st.subheader("Raw extracted features")
        st.dataframe(features_df, use_container_width=True)

        st.subheader("Download outputs")

        for label, path in outputs.items():
            p = Path(path)
            st.download_button(
                label=f"Download {label}",
                data=p.read_bytes(),
                file_name=p.name,
                mime="text/csv" if p.suffix == ".csv" else "text/plain",
            )

        if delete_raw_pcap:
            try:
                pcap_path.unlink()
                st.info("Raw uploaded pcap deleted from server after analysis.")
            except Exception as e:
                st.warning(f"Could not delete raw pcap: {e}")
        else:
            st.warning(f"Raw uploaded pcap retained at: {pcap_path}")

    except Exception as e:
        st.error(f"Analysis failed: {e}")
        st.exception(e)

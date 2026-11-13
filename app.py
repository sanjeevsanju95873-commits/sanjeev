"""
app.py - Interactive monitoring dashboard for the AV7SCM Mini-SIEM (Login Alert Assistant).

Run with:  streamlit run app.py
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

import database
import detector

st.set_page_config(
    page_title="AV7SCM Mini-SIEM",
    page_icon="🛡️",
    layout="wide",
)

database.init_db()


def build_checklist(alert: dict) -> list[str]:
    """Build the incident response steps for a given alert."""
    ip = alert["source_ip"]
    usernames = database.fetch_failed_usernames(ip)
    accounts = ", ".join(usernames) if usernames else "all targeted accounts"
    return [
        f"Step 1: Block source IP {ip} on the firewall / router",
        f"Step 2: Force a password reset for targeted accounts ({accounts})",
        f"Step 3: Verify historical logs for any successful login from {ip}",
        "Step 4: Enable two-step verification (MFA) on the affected accounts",
        "Step 5: Document the incident and notify staff to watch for suspicious activity",
    ]


def build_text_report(alert: dict, steps: list[str], states: list[bool]) -> str:
    """Create the formatted Incident Mitigation Report from live checkbox states."""
    done = sum(1 for state in states if state)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "=" * 70,
        "AV7SCM MINI-SIEM - INCIDENT MITIGATION REPORT",
        "=" * 70,
        f"Report generated : {generated}",
        f"Alert ID         : {alert['alert_id']}",
        f"Severity         : {alert['severity']}",
        f"Source IP        : {alert['source_ip']}",
        f"Failed attempts  : {alert['failed_attempts']}",
        f"Trigger time     : {alert['trigger_time']}",
        "",
        "-" * 70,
        f"MITIGATION PROGRESS: {done} of {len(steps)} steps completed",
        "-" * 70,
    ]
    for step, state in zip(steps, states):
        lines.append(f"[{'X' if state else ' '}] {step}")
    lines += [
        "",
        "-" * 70,
        "PLAIN-LANGUAGE GUIDANCE",
        "-" * 70,
        alert["remediation_message"],
        "",
        "=" * 70,
        "STATUS: " + ("ALL STEPS COMPLETE" if done == len(steps) else "ACTION STILL REQUIRED"),
        "=" * 70,
    ]
    return "\n".join(lines)


def build_csv_report(alert: dict, steps: list[str], states: list[bool]) -> str:
    """Create a CSV version of the checklist status."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["alert_id", "severity", "source_ip", "trigger_time", "step", "completed"])
    for step, state in zip(steps, states):
        writer.writerow(
            [
                alert["alert_id"],
                alert["severity"],
                alert["source_ip"],
                alert["trigger_time"],
                step,
                "yes" if state else "no",
            ]
        )
    return buffer.getvalue()


# ---------------------------------------------------------------- Sidebar ingestion
with st.sidebar:
    st.header("📥 Log Ingestion")
    st.caption("Upload JSON log telemetry, then run the detection engine.")
    uploaded = st.file_uploader("Drag and drop a JSON log file", type=["json"])
    run_clicked = st.button("Execute Stream Analysis", type="primary", use_container_width=True)

    if run_clicked:
        if uploaded is None:
            st.warning("Please upload a JSON log file first.")
        else:
            try:
                content = uploaded.getvalue().decode("utf-8-sig")
            except UnicodeDecodeError:
                st.session_state["last_result"] = {
                    "success": False,
                    "error": "The file is not valid UTF-8 text.",
                }
            else:
                with st.spinner("Analyzing log stream..."):
                    st.session_state["last_result"] = detector.process_log_data(content)

    result = st.session_state.get("last_result")
    if result:
        if result.get("success"):
            st.success(
                f"Analysis complete: {result['events_processed']} events audited, "
                f"{result['alerts_generated']} alert(s) raised, "
                f"{result['invalid_records']} record(s) skipped."
            )
        else:
            st.error(result.get("error") or "Analysis failed.")

# ---------------------------------------------------------------- Header and KPIs
st.title("🛡️ AV7SCM Mini-SIEM — Login Alert Assistant")
st.caption("Lightweight brute-force login detection with plain-language response guidance.")

total_events = database.fetch_event_count()
critical_alerts = database.fetch_alert_count("CRITICAL")

kpi_a, kpi_b = st.columns(2)
kpi_a.metric("Total Log Objects Audited", f"{total_events:,}")
kpi_b.metric("Active High-Severity Alerts", f"{critical_alerts:,}")

st.divider()

# ---------------------------------------------------------------- Alerts feed
st.subheader("🚨 Live Threat Alerts Feed")
alerts = database.fetch_alerts()

if not alerts:
    st.info("No alerts yet. Upload a log file in the sidebar and click 'Execute Stream Analysis'.")
else:
    table = pd.DataFrame(alerts).rename(
        columns={
            "alert_id": "Alert ID",
            "severity": "Severity",
            "source_ip": "Source IP",
            "failed_attempts": "Failed Attempts",
            "trigger_time": "Trigger Time (UTC)",
            "remediation_message": "Remediation Message",
        }
    )
    st.dataframe(table, use_container_width=True, hide_index=True)

    st.divider()

    # ------------------------------------------------------------ Action center
    st.subheader("🧰 Interactive Incident Action Center")

    alert_lookup = {alert["alert_id"]: alert for alert in alerts}
    selected_id = st.selectbox(
        "Select an alert to investigate",
        options=list(alert_lookup.keys()),
        format_func=lambda aid: (
            f"Alert #{aid} — {alert_lookup[aid]['source_ip']} — "
            f"{alert_lookup[aid]['severity']} — {alert_lookup[aid]['trigger_time']}"
        ),
    )

    selected = database.fetch_alert_by_id(selected_id)
    if selected:
        left, right = st.columns([1, 1])

        with left:
            st.markdown("#### Mitigation Checklist")
            steps = build_checklist(selected)
            states = [
                st.checkbox(step, key=f"alert_{selected['alert_id']}_step_{index}")
                for index, step in enumerate(steps)
            ]
            done = sum(1 for state in states if state)
            st.progress(done / len(steps), text=f"{done} of {len(steps)} steps completed")

        with right:
            st.markdown("#### Plain-Language Guidance")
            st.text(selected["remediation_message"])

        st.markdown("#### Export")
        report_text = build_text_report(selected, steps, states)
        report_csv = build_csv_report(selected, steps, states)
        export_a, export_b = st.columns(2)
        export_a.download_button(
            "⬇️ Download Incident Mitigation Report (.txt)",
            data=report_text,
            file_name=f"incident_report_alert_{selected['alert_id']}.txt",
            mime="text/plain",
            use_container_width=True,
        )
        export_b.download_button(
            "⬇️ Download Checklist Summary (.csv)",
            data=report_csv,
            file_name=f"incident_checklist_alert_{selected['alert_id']}.csv",
            mime="text/csv",
            use_container_width=True,
        )

import streamlit as st
import pandas as pd
import plotly.express as px
import socket
import re
import base64
import os

from utils.virustotal_api import scan_url
from utils.ip_lookup import get_ip_info
from utils.threat_engine import analyze_threat
from utils.ml_detector import predict_url, explain_url
from utils.sms_detector import predict_message, explain_message
from utils.logger import save_scan
from utils.analytics import (
    load_stats,
    get_recent_scans
)

# ---------------- PAGE CONFIG ---------------- #

st.set_page_config(
    page_title="AI Threat Intelligence System",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- LOAD BACKGROUND IMAGE ---------------- #

def get_base64_image(image_path):

    if not os.path.exists(image_path):
        return ""

    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

bg_image = get_base64_image("images/cyber_bg.jpg")

# ---------------- CUSTOM CSS ---------------- #

st.markdown(f"""
<style>

html, body, [class*="css"] {{
    font-family: 'Segoe UI', sans-serif;
}}

.stApp {{
    background:
        linear-gradient(
            rgba(3, 8, 20, 0.82),
            rgba(3, 8, 20, 0.90)
        ),
        url("data:image/jpeg;base64,{bg_image}");

    background-size: cover;
    background-position: center;
    background-attachment: fixed;
}}

.main-title {{
    font-size: 52px;
    font-weight: 700;
    color: white;
    text-align: center;
    margin-top: 10px;
}}

.subtitle {{
    text-align: center;
    color: #b7c9e6;
    font-size: 20px;
    margin-bottom: 35px;
}}

.section-card {{
    background: rgba(10, 18, 35, 0.82);
    border: 1px solid rgba(255,255,255,0.08);
    padding: 30px;
    border-radius: 20px;
    backdrop-filter: blur(12px);
    margin-bottom: 30px;
    transition: 0.4s ease;
}}

.section-card:hover {{
    transform: translateY(-5px);
    border: 1px solid rgba(0,255,255,0.25);
    box-shadow: 0px 0px 25px rgba(0,255,255,0.08);
}}

.section-title {{
    color: #00e5ff;
    font-size: 30px;
    font-weight: 700;
    margin-bottom: 20px;
}}

.result-box {{
    background: rgba(255,255,255,0.05);
    border-radius: 16px;
    padding: 20px;
    margin-top: 20px;
}}

.safe {{
    color: #00ff95;
    font-size: 30px;
    font-weight: bold;
}}

.suspicious {{
    color: #ffc857;
    font-size: 30px;
    font-weight: bold;
}}

.malicious {{
    color: #ff4d6d;
    font-size: 30px;
    font-weight: bold;
}}

.footer {{
    text-align:center;
    color:#8fa5c9;
    margin-top:40px;
    font-size:14px;
}}

.stButton>button {{
    background: linear-gradient(90deg,#00c6ff,#0072ff);
    color: white;
    border: none;
    border-radius: 12px;
    padding: 12px 28px;
    font-size: 16px;
    font-weight: 600;
    transition: 0.3s ease;
}}

.stButton>button:hover {{
    transform: scale(1.04);
    box-shadow: 0px 0px 15px rgba(0,255,255,0.35);
}}

.stTextInput input,
textarea {{
    background-color: rgba(255,255,255,0.08) !important;
    color: white !important;
    border-radius: 12px !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
}}
.metric-card{{
    background:linear-gradient(
        145deg,
        rgba(17,25,40,.88),
        rgba(13,18,28,.95)
    );
    border:1px solid rgba(0,229,255,.15);
    border-radius:20px;
    padding:22px;
    text-align:center;
    transition:.35s;
    backdrop-filter:blur(18px);
    box-shadow:0 10px 30px rgba(0,0,0,.35);
}}

.metric-card:hover{{
    transform:translateY(-6px);
    border:1px solid #00e5ff;
    box-shadow:0 0 25px rgba(0,229,255,.25);
}}

.metric-number{{
    font-size:42px;
    color:white;
    font-weight:700;
    margin-top:10px;
}}

.metric-title{{
    color:#8fb4d8;
    font-size:15px;
    letter-spacing:1px;
}}

.metric-icon{{
    font-size:34px;
}}
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ---------------- #

st.markdown(
    '<div class="main-title">🛡️ AI-Powered Phishing & Threat Intelligence System</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Advanced Cybersecurity Threat Detection using AI + Threat Intelligence + Machine Learning</div>',
    unsafe_allow_html=True
)

# ---------------- SIDEBAR ---------------- #

st.sidebar.title("📌 Navigation")

section = st.sidebar.radio(
    "",
    [
        "📊 Dashboard",
        "🔍 Threat Scanner",
        "✉️ Message Scanner",
        "🌐 Threat Intelligence",
        "🕒 Logs"
    ]
)

# ---------------- DASHBOARD ---------------- #

if section == "📊 Dashboard":
    stats = load_stats()


    st.markdown("## 📊 Security Operations Dashboard")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-number">{stats["total"]}</div>
            <div class="metric-title">Total Scans</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-number">{stats["safe"]}</div>
            <div class="metric-title">Safe</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-number">{stats["suspicious"]}</div>
            <div class="metric-title">Suspicious</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-number">{stats["malicious"]}</div>
            <div class="metric-title">Malicious</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("### 🚨 Threat Summary")
    risk_score = (
        stats["malicious"] * 10 +
        stats["suspicious"] * 5
    )

    col1, col2,col3 = st.columns(3)

    with col1:
        st.error(
            f"🔴 Malicious Scans: {stats['malicious']}"
        )

    with col2:
        st.warning(
            f"🟠 Suspicious Scans: {stats['suspicious']}"
        )
    with col3:

        if risk_score >= 20:
            st.error("🔴 HIGH RISK")

        elif risk_score >= 10:
            st.warning("🟠 MEDIUM RISK")

        else:
            st.success("🟢 LOW RISK")

    

    if risk_score >= 20:

        st.error(
            "⚠️ Current Security Risk Level: HIGH"
        )

    elif risk_score >= 10:

        st.warning(
            "⚠️ Current Security Risk Level: MEDIUM"
        )

    else:

        st.success(
            "✅ Current Security Risk Level: LOW"
        )
    st.markdown("### 📈 Threat Trend Analysis")

    try:
        df = pd.read_csv("logs/scan_history.csv")
    except FileNotFoundError:
        df = pd.DataFrame(columns=["Timestamp", "Input", "ThreatScore", "Classification"])

    if not df.empty:

        trend_fig = px.line(
            df,
            x="Timestamp",
            y="ThreatScore",
            markers=True,
            title="Threat Score Timeline"
        )

        trend_fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            height=450,
            xaxis_title="Scan Time",
            yaxis_title="Threat Score"
        )

        st.plotly_chart(
            trend_fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )
    
    st.markdown("### Recent Scan Activity")

    recent_df = get_recent_scans()

    if not recent_df.empty:

        st.dataframe(
        recent_df.sort_values(
            by="Timestamp",
            ascending=False
        ),
        use_container_width=True,
        height=350,
        hide_index=True
    )

    else:

        st.info(
            "No scan history available yet."
        )

        

# ---------------- THREAT SCANNER ---------------- #

elif section == "🔍 Threat Scanner":

    st.markdown('<div class="section-card">', unsafe_allow_html=True)

    st.markdown(
        '<div class="section-title">🔍 Threat Scanner</div>',
        unsafe_allow_html=True
    )

    user_input = st.text_area(
        "Enter suspicious URL or message",
        height=180
    )

    scan_btn = st.button("🚀 Scan Now")

    if scan_btn and user_input:

        urls = re.findall(
            r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})',
            user_input
        )
        st.write("Detected URLs:", urls)

        if urls:

            if not urls[0].startswith("http"):
                urls[0] = "https://" + urls[0]

        # ---------------- THREAT ENGINE ---------------- #

        threat_score, indicators, trusted_detected = analyze_threat(
            user_input,
            urls
        )

        # ---------------- AI ML DETECTION ---------------- #

        if urls:

            st.markdown(
                '<div class="section-title">🤖 AI ML Detection</div>',
                unsafe_allow_html=True
            )

            prediction, confidence = predict_url(urls[0])

            ml_score = int(confidence)

            # ML model contribution.
            #
            # A curated trusted-domain match is a stronger signal than
            # the ML model's guess — the model is known to sometimes
            # misfire on short, well-known, brand-name domains (see
            # README "Bugs found & fixed"). So a trusted domain gets
            # only a small, non-decisive bump from a "phishing" ML
            # call instead of the full penalty, while VirusTotal
            # (checked next, and independent of both signals) can
            # still override everything if it finds real evidence.

            if prediction == 1:

                if trusted_detected:
                    threat_score += 5
                    indicators.append(
                        "AI model flagged this URL, but it matches a trusted domain — treated as low-confidence"
                    )
                else:
                    threat_score += 30
                    indicators.append(
                        "AI model detected phishing patterns"
                    )

            ml_prediction = "Phishing" if prediction == 1 else "Safe"

        # ---------------- VIRUSTOTAL ---------------- #

        vt_data = None

        if urls:

            try:
                vt_data = scan_url(urls[0])

                if "error" in vt_data:
                    st.warning(f"VirusTotal API Error: {vt_data['error']}")

            except Exception as e:
                st.warning(f"VirusTotal unavailable: {e}")
                vt_data = None

            if vt_data and "error" not in vt_data:

                malicious = vt_data.get("malicious", 0)
                suspicious = vt_data.get("suspicious", 0)

                threat_score += malicious * 10
                threat_score += suspicious * 5

                if malicious > 0:

                    indicators.append(
                        f"VirusTotal detected {malicious} malicious engines"
                    )

        # ---------------- LIMIT SCORE ---------------- #

        if threat_score > 100:
            threat_score = 100

        # ---------------- FINAL RESULT ---------------- #

        st.markdown(
            '<div class="section-title">📊 Scan Result</div>',
            unsafe_allow_html=True
        )
        if threat_score >= 70:

            result_class = "malicious"
            result_text = "🔴 Malicious Content"
            classification = "Malicious"

        elif threat_score >= 35:

            result_class = "suspicious"
            result_text = "🟠 Suspicious Content"
            classification = "Suspicious"

        else:

            result_class = "safe"
            result_text = "🟢 Safe Content"
            classification = "Safe"

        st.markdown("### 🤖 AI Final Decision")

        if classification == "Malicious":

            st.error(
                f"Final AI Verdict: {classification}"
            )

        elif classification == "Suspicious":

            st.warning(
                f"Final AI Verdict: {classification}"
            )

        else:

            st.success(
                f"Final AI Verdict: {classification}"
            )

        st.caption(
            f"Raw ML Model: {ml_prediction} ({ml_score}% confidence)"
        )

        # ---------------- EXPLAINABILITY ---------------- #

        if urls:

            explanation = explain_url(urls[0])

            if explanation["phishing_signals"] or explanation["safe_signals"]:

                with st.expander("🔍 Why did the AI decide this? (feature attribution)"):

                    st.caption(
                        "These are the exact character patterns in the URL that pushed "
                        "the model's decision, ranked by influence — the same "
                        "underlying math as a SHAP linear explanation."
                    )

                    if explanation["phishing_signals"]:
                        st.markdown("**Pushed toward Phishing:**")
                        for ngram, contribution in explanation["phishing_signals"]:
                            st.write(f"`{ngram}` — influence: {contribution:.3f}")

                    if explanation["safe_signals"]:
                        st.markdown("**Pushed toward Safe:**")
                        for ngram, contribution in explanation["safe_signals"]:
                            st.write(f"`{ngram}` — influence: {contribution:.3f}")

        # ---------------- SAVE SCAN LOG ---------------- #
        save_scan(
            user_input,
            threat_score,
            classification
        )
        st.markdown(
            f"""
            <div class="result-box">
                <div class="{result_class}">
                    {result_text} (Score: {threat_score}/100)
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # ---------------- THREAT INDICATORS ---------------- #

        st.markdown(
            '<div class="section-title">🚨 Threat Indicators</div>',
            unsafe_allow_html=True
        )

        if indicators:

            for item in indicators:
                st.warning(item)

        else:
            st.success("No major cyber threat indicators found.")

        # ---------------- PIE CHART ---------------- #

        st.markdown(
            '<div class="section-title">📈 Threat Visualization</div>',
            unsafe_allow_html=True
        )

        safe_value = max(0, 100 - threat_score)

        chart_data = pd.DataFrame({
            "Category": ["Threat", "Safe"],
            "Value": [threat_score, safe_value]
        })

        fig = px.pie(
            chart_data,
            names="Category",
            values="Value",
            hole=0.55
        )

        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            width=450,
            height=350
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
            config={
                "displayModeBar": False,
                "staticPlot": True
            }
        )

        # ---------------- IP INTELLIGENCE ---------------- #

        if urls:

            st.markdown(
                '<div class="section-title">🌐 IP Intelligence</div>',
                unsafe_allow_html=True
            )

            try:

                domain = urls[0] \
                    .replace("https://", "") \
                    .replace("http://", "") \
                    .split("/")[0]

                ip = socket.gethostbyname(domain)

                ip_info = get_ip_info(ip)

                if ip_info:

                    st.info(f"🌍 IP Address: {ip}")
                    st.info(f"🏳️ Country: {ip_info.get('country')}")
                    st.info(f"🏢 ISP: {ip_info.get('org')}")

            except:
                st.error("Unable to fetch IP intelligence.")

        # ---------------- VIRUSTOTAL DISPLAY ---------------- #

        if vt_data:

            st.markdown(
                '<div class="section-title">🛡️ VirusTotal Intelligence</div>',
                unsafe_allow_html=True
            )

            st.info(
                f"🔴 Malicious Engines: {vt_data.get('malicious', 0)}"
            )

            st.info(
                f"🟠 Suspicious Engines: {vt_data.get('suspicious', 0)}"
            )

            st.info(
                f"🟢 Harmless Engines: {vt_data.get('harmless', 0)}"
            )

    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- MESSAGE SCANNER ---------------- #

elif section == "✉️ Message Scanner":

    st.markdown('<div class="section-card">', unsafe_allow_html=True)

    st.markdown(
        '<div class="section-title">✉️ SMS / Email Message Scanner</div>',
        unsafe_allow_html=True
    )

    st.caption(
        "Paste the text of a suspicious SMS or email to check it for "
        "phishing / spam patterns, separate from URL analysis."
    )

    message_input = st.text_area(
        "Enter message text",
        height=180,
        key="message_input"
    )

    msg_scan_btn = st.button("🚀 Scan Message")

    if msg_scan_btn and message_input:

        prediction, confidence = predict_message(message_input)

        ml_score = int(confidence)

        # Reuse the rule-based engine for indicator explanations
        urls_in_msg = re.findall(
            r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,})',
            message_input
        )
        rule_score, indicators, trusted_detected = analyze_threat(message_input, urls_in_msg)

        is_spam = prediction == 1

        if is_spam:
            indicators.append("AI model classified this message as spam/phishing-style")
            threat_score = max(rule_score, ml_score)
        else:
            # ML says this isn't spam — trust the rule engine's own
            # assessment rather than trying to blend in the "safe"
            # confidence score, which doesn't map cleanly onto a
            # threat score.
            threat_score = rule_score

        threat_score = max(0, min(threat_score, 100))

        st.markdown(
            '<div class="section-title">📊 Scan Result</div>',
            unsafe_allow_html=True
        )

        if threat_score >= 70:
            result_class = "malicious"
            result_text = "🔴 Malicious / Phishing Message"
            classification = "Malicious"
        elif threat_score >= 35:
            result_class = "suspicious"
            result_text = "🟠 Suspicious Message"
            classification = "Suspicious"
        else:
            result_class = "safe"
            result_text = "🟢 Safe Message"
            classification = "Safe"

        st.markdown("### 🤖 AI Final Decision")

        if classification == "Malicious":
            st.error(f"Final AI Verdict: {classification}")
        elif classification == "Suspicious":
            st.warning(f"Final AI Verdict: {classification}")
        else:
            st.success(f"Final AI Verdict: {classification}")

        raw_label = "Spam / Phishing-style" if is_spam else "Legitimate"
        st.caption(f"Raw ML Model: {raw_label} ({ml_score}% confidence)")

        # ---------------- EXPLAINABILITY ---------------- #

        msg_explanation = explain_message(message_input)

        if msg_explanation["spam_signals"] or msg_explanation["ham_signals"]:

            with st.expander("🔍 Why did the AI decide this? (feature attribution)"):

                st.caption(
                    "These are the exact words/phrases that pushed the model's "
                    "decision, ranked by influence — the same underlying math as "
                    "a SHAP linear explanation."
                )

                if msg_explanation["spam_signals"]:
                    st.markdown("**Pushed toward Spam/Phishing:**")
                    for word, contribution in msg_explanation["spam_signals"]:
                        st.write(f"`{word}` — influence: {contribution:.3f}")

                if msg_explanation["ham_signals"]:
                    st.markdown("**Pushed toward Legitimate:**")
                    for word, contribution in msg_explanation["ham_signals"]:
                        st.write(f"`{word}` — influence: {contribution:.3f}")

        save_scan(message_input, threat_score, classification)

        st.markdown(
            f"""
            <div class="result-box">
                <div class="{result_class}">
                    {result_text} (Score: {threat_score}/100)
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="section-title">🚨 Threat Indicators</div>',
            unsafe_allow_html=True
        )

        if indicators:
            for item in indicators:
                st.warning(item)
        else:
            st.success("No major phishing indicators found.")

    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- THREAT INTELLIGENCE ---------------- #

elif section == "🌐 Threat Intelligence":
    st.subheader("🌐 Threat Intelligence Center")
    try:
        df = pd.read_csv("logs/scan_history.csv")
    except:
        df = pd.DataFrame(
            columns=[
                "Timestamp",
                "Input",
                "ThreatScore",
                "Classification"
            ]
        )
    total_scans = len(df)

    safe_count = len(
        df[df["Classification"] == "Safe"]
    )

    suspicious_count = len(
        df[df["Classification"] == "Suspicious"]
    )

    malicious_count = len(
        df[df["Classification"] == "Malicious"]
    )

    if total_scans > 0:

        avg_score = round(
            df["ThreatScore"].mean(),
            1
        )

    else:

        avg_score = 0
        
    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Total Scans",
            total_scans
        )

    with col2:

        st.metric(
            "Safe",
            safe_count
        )

    with col3:

        st.metric(
            "Suspicious",
            suspicious_count
        )

    with col4:

        st.metric(
            "Malicious",
            malicious_count
        )

    # ---------------- AVERAGE SCORE ---------------- #

    st.markdown("## 🎯 Average Threat Score")

    st.progress(avg_score / 100)

    st.markdown(
        f"<h3 style='color:#00e5ff'>{avg_score}/100</h3>",
        unsafe_allow_html=True
    )
    st.markdown("---")
    st.subheader("📊 Threat Distribution")

    chart_df = pd.DataFrame({
        "Category": [
            "Safe",
            "Suspicious",
            "Malicious"
        ],
        "Count": [
            safe_count,
            suspicious_count,
            malicious_count
        ]
    })

    fig = px.pie(
        chart_df,
        names="Category",
        values="Count",
        hole=0.60
    )

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        height=420,
        showlegend=True
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
        config={
            "displayModeBar": False,
            "staticPlot": True
        }
    )
    st.markdown("---")
    st.subheader("📈 Threat Trend")

    if not df.empty:

        trend_fig = px.line(
            df,
            x="Timestamp",
            y="ThreatScore",
            markers=True,
            title="Threat Score Over Time"
        )

        trend_fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            height=450,
            xaxis_title="Scan Time",
            yaxis_title="Threat Score"
        )

        st.plotly_chart(
            trend_fig,
            use_container_width=True,
            config={
                "displayModeBar": False,
                "staticPlot": True
            }
        )

    else:

        st.info("No scan history available.")

    st.markdown("## 🌐 Threat Intelligence Center")

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "VirusTotal Checks",
            len(df)
        )

        st.metric(
            "Malicious Engines",
            "N/A"
        )

    with col2:

        st.metric(
            "Suspicious Engines",
            "N/A"
        )

        st.metric(
            "Harmless Engines",
            "N/A"
        )
    st.markdown("---")

    st.markdown("### 🎯 Detection Capabilities")

    capabilities = pd.DataFrame({

        "Feature": [
            "AI Phishing Detection",
            "VirusTotal Intelligence",
            "IP Reputation Analysis",
            "Social Engineering Detection",
            "Threat Scoring Engine"
        ],

        "Status": [
            "Active",
            "Active",
            "Active",
            "Active",
            "Active"
        ]
    })

    st.dataframe(
        capabilities,
        use_container_width=True,
        hide_index=True
    )

# ---------------- LOGS ---------------- #

elif section == "🕒 Logs":
    try:
        df = pd.read_csv("logs/scan_history.csv")
    except:
        df = pd.DataFrame()

    st.markdown("## 🕒 Scan History")

    st.dataframe(
        df.sort_values(
            by="Timestamp",
            ascending=False
        ),
        use_container_width=True,
        height=500,
        hide_index=True
    )

# ---------------- FOOTER ---------------- #

st.markdown(
    """
    <div class="footer">
        🔐 Powered by AI, Machine Learning & Cybersecurity Intelligence
    </div>
    """,
    unsafe_allow_html=True
)
import os
from dotenv import load_dotenv
import streamlit as st
from ip_domain_checker import check_domain_vt

# ---------------- LOAD ENV ----------------
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="ThreatDash",
    page_icon="🛡",
    layout="wide"
)

# ---------------- TITLE ----------------
st.title("🛡 ThreatDash – Personal Threat Intelligence Dashboard")

# ---------------- SIDEBAR INPUTS ----------------
st.sidebar.header("Scan Inputs")
email = st.sidebar.text_input("📧 Enter Digital Identity (Email / Username)")
domain = st.sidebar.text_input("🌐 Enter domain or IP")

# =================================================
# 📧 EMAIL BREACH SECTION (PAID API HANDLED CLEANLY)
# =================================================
if email:
    st.subheader("📧 Email Breach Risk")

    st.warning("Email breach lookup is disabled (Have I Been Pwned requires a paid API key).")

    # Clean metric instead of raw JSON
    st.metric(
        label="Email Risk Level",
        value="Medium",
        help="Based on public breach datasets (demo data)"
    )

# =================================================
# 🌐 DOMAIN / IP THREAT ANALYSIS (VIRUSTOTAL)
# =================================================
if domain:
    st.subheader("🌐 Domain / IP Risk Analysis")

    # ---- Block private IPs ----
    if domain.startswith(("192.168.", "10.", "172.")):
        st.warning("Private IP addresses are not scannable via VirusTotal.")
    else:
        if not VT_API_KEY:
            st.error("VirusTotal API key not loaded. Check your .env file.")
        else:
            vt_info = check_domain_vt(domain, VT_API_KEY)

            if "error" in vt_info:
                st.error(f"VirusTotal API Error: {vt_info['error']}")
            else:
                attrs = vt_info.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                total_engines = sum(stats.values()) if stats else 0

                reputation = attrs.get("reputation", 0)
                country = attrs.get("country", "Unknown")
                asn_owner = attrs.get("as_owner", "Unknown")

                # ---- Risk Level ----
                if malicious > 0:
                    risk = "🔴 High Risk"
                elif suspicious > 0:
                    risk = "🟡 Medium Risk"
                else:
                    risk = "🟢 Low Risk"

                st.markdown(f"### Risk Level\n**{risk}**")

                # ---- Detections ----
                st.write(f"**Detections:** {malicious + suspicious} / {total_engines}")
                st.write(f"**Country:** {country}")
                st.write(f"**ASN Owner:** {asn_owner}")
                st.write(f"**Reputation Score:** {reputation}")

                # ---- Confidence Bar (🔥) ----
                st.markdown("### Confidence Score")
                st.progress(min(reputation / 1000, 1.0))

                # ---- External Report ----
                vt_id = vt_info.get("data", {}).get("id")
                if vt_id:
                    st.markdown(
                        f"[🔍 View Full VirusTotal Report](https://www.virustotal.com/gui/search/{vt_id})",
                        unsafe_allow_html=True
                    )

import streamlit as st
import urllib.parse
import re

st.title("Phishing URL Scanner")

if "history" not in st.session_state:
    st.session_state.history = []

def scan_url(url):
    score = 0
    reasons = []

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ""
    url_lower = url.lower()

    keywords = ["login", "verify", "secure", "account", "update", "bank", "password"]

    for word in keywords:
        if word in url_lower:
            score += 10
            reasons.append(f"Suspicious keyword detected: {word}")

    if len(url) > 75:
        score += 10
        reasons.append("URL length suspicious")

    if hostname.count(".") > 3:
        score += 10
        reasons.append("Too many subdomains")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 20
        reasons.append("IP address used instead of domain")

    suspicious_tlds = ["xyz", "top", "zip", "click", "gq"]

    for tld in suspicious_tlds:
        if hostname.endswith("." + tld):
            score += 15
            reasons.append(f"Suspicious domain extension: .{tld}")

    if score >= 40:
        verdict = "High Risk"
    elif score >= 15:
        verdict = "Medium Risk"
    else:
        verdict = "Low Risk"

    return score, verdict, reasons


url = st.text_input("Enter URL to scan")

if st.button("Scan URL"):

    score, verdict, reasons = scan_url(url)

    st.session_state.history.append({
        "URL": url,
        "Score": score,
        "Verdict": verdict
    })

    st.subheader("Scan Results")

    if verdict == "Low Risk":
        st.success(f"Verdict: {verdict}")
    elif verdict == "Medium Risk":
        st.warning(f"Verdict: {verdict}")
    else:
        st.error(f"Verdict: {verdict}")

    st.write("Risk Score:", score)

    st.write("Reasons:")

    if reasons:
        for r in reasons:
            st.write("-", r)
    else:
        st.write("No suspicious indicators detected.")

st.subheader("Scan History")

if st.session_state.history:
    st.table(st.session_state.history)
else:
    st.write("No scans yet.")
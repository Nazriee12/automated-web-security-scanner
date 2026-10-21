import ipaddress
import socket
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="Automated Web Security Scanner", page_icon="🛡️", layout="wide")

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "purpose": "Helps reduce the risk of content injection by defining allowed content sources.",
        "recommendation": "Review and configure a Content-Security-Policy suitable for the website."
    },
    "Strict-Transport-Security": {
        "purpose": "Instructs browsers to use HTTPS for future connections.",
        "recommendation": "Consider HSTS after confirming HTTPS is correctly configured."
    },
    "X-Content-Type-Options": {
        "purpose": "Helps prevent MIME-type sniffing by browsers.",
        "recommendation": "Consider setting X-Content-Type-Options: nosniff."
    },
    "Referrer-Policy": {
        "purpose": "Controls how much referrer information browsers send.",
        "recommendation": "Choose a suitable Referrer-Policy for the website."
    },
    "Permissions-Policy": {
        "purpose": "Lets a website restrict access to selected browser features.",
        "recommendation": "Set a Permissions-Policy appropriate for the site's features."
    },
    "X-Frame-Options": {
        "purpose": "Can help protect against clickjacking in supporting browsers.",
        "recommendation": "Consider X-Frame-Options or CSP frame-ancestors, as appropriate."
    },
}


def normalize_url(raw_url):
    """Validate and normalize a supplied HTTP(S) URL."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Please enter a website URL.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not accepted.")
    return raw_url


def public_hostname(hostname):
    """Return True only if all resolved addresses are public/global addresses."""
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            addresses = [
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            ]
        except (socket.gaierror, OSError):
            return False
    return bool(addresses) and all(address.is_global for address in addresses)


def scan_website(raw_url):
    """Request a public website and check selected HTTP response headers."""
    url = normalize_url(raw_url)
    parsed = urlparse(url)

    # This educational scanner is intended for public hosts only.
    if not public_hostname(parsed.hostname):
        raise ValueError(
            "This scanner only checks publicly reachable hosts. "
            "Local, private, reserved, and unresolved hosts are blocked."
        )

    # Redirects are not followed, reducing the risk of redirects to private hosts.
    response = requests.get(
        url,
        timeout=10,
        allow_redirects=False,
        headers={"User-Agent": "AutomatedWebSecurityScanner/1.0"},
        stream=True,
    )
    try:
        response_headers = dict(response.headers)
        status_code = response.status_code
        response_url = response.url
    finally:
        response.close()

    results = []
    for header, details in SECURITY_HEADERS.items():
        present = header in response_headers
        results.append({
            "Security Header": header,
            "Status": "Present" if present else "Missing",
            "Purpose": details["purpose"],
            "Recommendation": (
                "No action indicated by this header check."
                if present else details["recommendation"]
            ),
        })

    return url, status_code, response_url, results, response_headers


st.title("🛡️ Automated Web Security Scanner")
st.write(
    "A beginner-friendly defensive tool that checks common HTTP security headers "
    "and creates a downloadable report."
)
st.info(
    "Use only on websites you own or have explicit permission to assess. "
    "This tool checks response headers only; it is not a full vulnerability scanner."
)

with st.form("scan_form"):
    target_url = st.text_input("Website URL", placeholder="https://example.com")
    submitted = st.form_submit_button("Scan security headers", type="primary")

if submitted:
    try:
        with st.spinner("Checking response headers..."):
            url, status_code, response_url, results, response_headers = scan_website(target_url)

        result_df = pd.DataFrame(results)
        present_count = sum(row["Status"] == "Present" for row in results)
        missing_count = len(results) - present_count

        st.subheader("Scan summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("HTTP status code", status_code)
        col2.metric("Headers present", present_count)
        col3.metric("Headers missing", missing_count)

        st.caption(f"Requested URL: {url}")
        st.caption(f"Response URL (redirects are not followed): {response_url}")

        st.subheader("Security header results")
        st.dataframe(result_df, use_container_width=True, hide_index=True)

        st.subheader("Response headers")
        st.json(response_headers)

        st.download_button(
            "Download CSV report",
            data=result_df.to_csv(index=False).encode("utf-8"),
            file_name="web_security_scan_report.csv",
            mime="text/csv",
        )
        st.warning(
            "A missing header is a finding to review, not automatic proof of a vulnerability. "
            "Appropriate headers depend on the website and its architecture."
        )
    except requests.exceptions.SSLError:
        st.error(
            "HTTPS/TLS verification failed. Check the URL and certificate. "
            "Do not disable certificate verification to force a scan."
        )
    except requests.exceptions.Timeout:
        st.error("The website took too long to respond. Try again later.")
    except requests.exceptions.RequestException as exc:
        st.error(f"Request failed: {exc}")
    except ValueError as exc:
        st.error(str(exc))
    except Exception:
        st.error("An unexpected error occurred. Check the URL and try again.")

st.divider()
st.caption("Educational project | Python | Streamlit | Requests | Pandas")

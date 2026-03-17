import streamlit as st
import pandas as pd
import tempfile
import os
import re
from email.utils import parseaddr
from email.header import decode_header
import olefile
from io import BytesIO

# ---------------------------------------------------------
# DKIM SELECTOR MASTER LIST
# ---------------------------------------------------------

DKIM_PROVIDERS = {
    "Google Workspace / Gmail": ["google", "selector1", "selector2"],
    "Microsoft 365 / Exchange Online": ["selector1", "selector2", "microsoft"],
    "Amazon SES": ["amazonses", "ses"],
    "SendGrid": ["s1", "s2", "sendgrid", "smtpapi"],
    "Mailgun": ["mailgun", "mg"],
    "Postmark": ["pm", "postmark"],
    "SparkPost": ["scph", "sparkpost"],
    "Salesforce Marketing Cloud": ["exacttarget", "sfdc", "salesforce", "50dkim1"],
    "Pardot": ["pardot"],
    "SAP Emarsys": ["key1", "key2", "key5", "key6", "10dkim1", "200608", "dkim0"],
    "Optimizely / Episerver / Optivo": ["mailing", "spop1024"],
    "June": ["junemail"],
    "Sendinblue / Brevo": ["newsletter2go"],
    "Inxmail": ["inx", "inxdeka", "abc"],
    "Mailchimp": ["k1", "k2", "mcsv", "mandrill"],
    "Mandrill (Mailchimp Transactional)": ["mandrill"],
    "Mapp": ["ecm1"],
    "Mailjet": ["mailjet"],
    "Selligent": ["slgntsdcapi", "sim"],
    "Agnitas": ["agn"],
    "Cheetah Digital": ["selsha01", "0", "sim"],
    "Artegic": ["elaine", "elaine-asp", "exch"],
    "promio.net": ["default"],
    "Experian": ["s20141100"],
    "DeployTeq": ["cd1", "cd2"],
    "Webanizer": ["m"],
    "HubSpot": ["hs1", "hs2"],
    "Klaviyo": ["kl"],
}

DKIM_DOMAIN_PROVIDERS = {
    "emarsys.net": "SAP Emarsys",
}

# ---------------------------------------------------------
# MATCHING LOGIK
# ---------------------------------------------------------

def match_dkim(selector: str, dkim_domain: str | None = None) -> str | None:
    selector_lower = (selector or "").strip().lower()

    if dkim_domain:
        dkim_domain = dkim_domain.strip().lower()
        for domain_pattern, esp in DKIM_DOMAIN_PROVIDERS.items():
            if domain_pattern in dkim_domain:
                return esp

    if selector_lower:
        for esp, keywords in DKIM_PROVIDERS.items():
            for key in keywords:
                k = key.lower()
                if selector_lower == k:
                    return esp
                if len(k) > 1 and selector_lower.startswith(k):
                    return esp

    return None

# ---------------------------------------------------------
# EXCEL EXPORT
# ---------------------------------------------------------

def to_excel(df):
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Analyse")

        worksheet = writer.sheets["Analyse"]

        # automatische Spaltenbreite
        for i, col in enumerate(df.columns):
            max_len = max(
                df[col].astype(str).map(len).max(),
                len(col)
            ) + 2
            worksheet.column_dimensions[chr(65 + i)].width = max_len

    return output.getvalue()

# ---------------------------------------------------------

st.set_page_config(page_title="MSG/EML Header Analyzer (final)", layout="wide")

st.title("MSG / EML Header Analyzer, ESP & Excel Download")

def decode_mime_words(s):
    parts = decode_header(s)
    out = ""
    for bytes_part, encoding in parts:
        if isinstance(bytes_part, bytes):
            try:
                out += bytes_part.decode(encoding or "utf-8", errors="ignore")
            except:
                out += bytes_part.decode("latin1", errors="ignore")
        else:
            out += bytes_part
    return out

def extract_from_eml(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except:
        text = raw.decode("latin1", errors="ignore")
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    return parts[0] if parts else text

def extract_from_msg(path: str) -> str | None:
    try:
        ole = olefile.OleFileIO(path)
    except Exception:
        return None

    candidates = []
    for entry in ole.listdir(streams=True, storages=False):
        name = "/".join(entry)
        if "007D001F" in name.upper() or "007D001E" in name.upper():
            try:
                data = ole.openstream(entry).read()
                candidates.append((name, data))
            except Exception:
                continue

    for try_name in ("__substg1.0_007D001F", "__substg1.0_007D001E"):
        if ole.exists(try_name):
            try:
                data = ole.openstream(try_name).read()
                candidates.insert(0, (try_name, data))
            except Exception:
                pass

    ole.close()

    if not candidates:
        return None

    for name, data in candidates:
        if "001F" in name.upper():
            try:
                return data.decode("utf-16-le", errors="ignore")
            except:
                pass

    for name, data in candidates:
        for enc in ("utf-8", "latin1", "cp1252"):
            try:
                return data.decode(enc, errors="ignore")
            except:
                continue

    return None

def parse_headers(headers: str) -> dict:
    result = {
        "dkim_domain_1": "-",
        "dkim_selector_1": "-",
        "dkim_itag_1": "-",
        "dkim_domain_2": "-",
        "dkim_selector_2": "-",
        "dkim_itag_2": "-",
        "email_versandtool": "Unbekannt",
        "from_domain": "-",
        "returnpath_domain": "-",
        "dkim_auth_result": "nicht vorhanden",
        "dkim_alignment": "kein Alignment",
        "headers_found": "yes" if headers else "no"
    }

    if not headers:
        return result

    normalized = re.sub(r"(\r?\n)[ \t]+", " ", headers)

    dkim_blocks = re.findall(r"(?mi)^dkim-signature:\s*(.+?)(?=\r?\n[^ \t]|$)", normalized, flags=re.S)

    def extract(block):
        d = re.search(r"\bd=([^;\s]+)", block, flags=re.I)
        s = re.search(r"\bs=([^;\s]+)", block, flags=re.I)
        i = re.search(r"\bi=([^;\s]+)", block, flags=re.I)
        return (
            d.group(1) if d else "-",
            s.group(1) if s else "-",
            i.group(1) if i else "-"
        )

    if dkim_blocks:
        result["dkim_domain_1"], result["dkim_selector_1"], result["dkim_itag_1"] = extract(dkim_blocks[0])
        if len(dkim_blocks) > 1:
            result["dkim_domain_2"], result["dkim_selector_2"], result["dkim_itag_2"] = extract(dkim_blocks[1])

    fm = re.search(r"(?mi)^from:\s*(.+)$", normalized)
    if fm:
        _, addr = parseaddr(decode_mime_words(fm.group(1)))
        if "@" in addr:
            result["from_domain"] = addr.split("@")[1].lower()

    return result

# ---------------------------------------------------------

uploaded_files = st.file_uploader(
    "MSG- oder EML-Dateien hochladen",
    type=["msg", "eml"],
    accept_multiple_files=True
)

if uploaded_files:
    results = []

    for up in uploaded_files:
        if up.name.lower().endswith(".eml"):
            headers = extract_from_eml(up.read())
        else:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
                tmp.write(up.read())
                tmp_path = tmp.name
            headers = extract_from_msg(tmp_path)
            os.remove(tmp_path)

        parsed = parse_headers(headers or "")
        results.append({"filename": up.name, **parsed})

    df = pd.DataFrame(results)

    st.subheader("Analyse-Ergebnisse")

    # ✅ EDITOR statt dataframe → kopierbar
    st.data_editor(df)

    # ✅ Excel Download
    excel_data = to_excel(df)

    st.download_button(
        "Excel herunterladen",
        data=excel_data,
        file_name="header_analysis.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

else:
    st.info("Bitte MSG- oder EML-Dateien hochladen…")
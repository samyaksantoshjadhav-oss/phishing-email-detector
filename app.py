import streamlit as st
import joblib
import re
import pandas as pd
from datetime import datetime
import os
import io
from utils import (
    check_suspicious_keywords,
    check_suspicious_domain,
    check_suspicious_links,
    classify_attack_type,
    calculate_threat_score,
    classify_risk_level,
    get_confidence_label,
)

# ── PDF ───────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ── PAGE CONFIG ───────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing Email Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── USER CREDENTIALS ──────────────────────────────────────────
USERS = {
    "admin":   {"password": "admin123",   "name": "Admin User",      "role": "Administrator"},
    "analyst": {"password": "analyst123", "name": "Security Analyst", "role": "Analyst"},
    "user1":   {"password": "pass123",    "name": "John Doe",         "role": "User"},
}

# ── HISTORY FILE ──────────────────────────────────────────────
history_file = "scan_history.csv"
if not os.path.exists(history_file):
    pd.DataFrame(columns=["time","sender","subject","risk","score","phishing_prob","legit_prob","prediction","domain_flag","keyword_flag","link_flag","ptype","conf_label","conf"]).to_csv(history_file, index=False)

# ── SESSION STATE ─────────────────────────────────────────────
if "logged_in"   not in st.session_state: st.session_state.logged_in   = False
if "username"    not in st.session_state: st.session_state.username    = ""
if "page"        not in st.session_state: st.session_state.page        = "dashboard"
if "last_result" not in st.session_state: st.session_state.last_result = None

# ── LOAD MODEL ────────────────────────────────────────────────
@st.cache_resource
def load_model():
    return joblib.load("models/phishing_model.pkl"), joblib.load("models/vectorizer.pkl")

model, vectorizer = load_model()

# ── PDF GENERATOR ─────────────────────────────────────────────
def generate_pdf_report(sender, subject, risk_level, threat_score,
                        phishing_prob, legit_prob, prediction,
                        domain_flag, keyword_flag, link_flag,
                        phishing_type, scan_time, confidence_label,
                        conf_index, scanned_by):
    buffer = io.BytesIO()
    W, H   = A4
    M      = 45
    RISK_COL = colors.HexColor("#CC0000") if risk_level=="HIGH" \
          else colors.HexColor("#E65C00") if risk_level=="MEDIUM" \
          else colors.HexColor("#1560FF")
    DARK=colors.HexColor("#111827"); LGREY=colors.HexColor("#9CA3AF")
    DIV=colors.HexColor("#E5E7EB"); BLACK=colors.black

    c = canvas.Canvas(buffer, pagesize=A4)
    c.setFillColor(RISK_COL); c.rect(0,H-5,W,5,fill=1,stroke=0)
    c.setFont("Helvetica-Bold",8); c.setFillColor(LGREY)
    c.drawString(M,H-22,"PHISHING EMAIL DETECTION SYSTEM  ·  CONFIDENTIAL THREAT REPORT")
    c.setFont("Helvetica",8); c.drawRightString(W-M,H-22,f"Generated: {scan_time}")
    c.drawRightString(W-M,H-32,f"Analyst: {scanned_by}")
    c.setStrokeColor(DIV); c.setLineWidth(0.8); c.line(M,H-38,W-M,H-38)
    c.setFont("Helvetica-Bold",24); c.setFillColor(DARK)
    c.drawString(M,H-70,"Email Threat Analysis Report")
    c.setFont("Helvetica",10); c.setFillColor(LGREY)
    c.drawString(M,H-86,"Automated scan · Hybrid ML + Rule-Based Detection Engine")
    bw=c.stringWidth(f"{risk_level} RISK","Helvetica-Bold",11)+24
    bx=W-M-bw
    c.setStrokeColor(RISK_COL); c.setLineWidth(1.5)
    c.setFillColor(RISK_COL); c.setFillAlpha(0.08)
    c.rect(bx,H-92,bw,24,fill=1,stroke=1); c.setFillAlpha(1)
    c.setFont("Helvetica-Bold",11); c.setFillColor(RISK_COL)
    c.drawCentredString(bx+bw/2,H-83,f"{risk_level} RISK")
    c.setStrokeColor(DARK); c.setLineWidth(1.5); c.line(M,H-100,W-M,H-100)
    y=H-124

    def sec(title,yp):
        c.setFont("Helvetica-Bold",10); c.setFillColor(DARK); c.drawString(M,yp,title)
        c.setStrokeColor(RISK_COL); c.setLineWidth(2); c.line(M,yp-5,M+28,yp-5)
        c.setStrokeColor(DIV); c.setLineWidth(0.5); c.line(M+28,yp-5,W-M,yp-5)
        return yp-20

    def kv(key,val,yp,col=None,bold=False):
        c.setFont("Helvetica",9); c.setFillColor(LGREY); c.drawString(M,yp,key)
        c.setFont("Helvetica-Bold" if bold else "Helvetica",9)
        c.setFillColor(col if col else BLACK); c.drawString(M+165,yp,str(val))
        c.setStrokeColor(DIV); c.setLineWidth(0.4); c.line(M,yp-5,W-M,yp-5)
        return yp-17

    def chk(label,flagged,yp):
        col=colors.HexColor("#CC0000") if flagged else colors.HexColor("#1560FF")
        c.setFont("Helvetica",9); c.setFillColor(DARK); c.drawString(M,yp,label)
        c.setFont("Helvetica-Bold",9); c.setFillColor(col)
        c.drawRightString(W-M,yp,"FLAGGED" if flagged else "PASSED")
        c.setStrokeColor(DIV); c.setLineWidth(0.4); c.line(M,yp-5,W-M,yp-5)
        return yp-17

    y=sec("1.  Email Details",y)
    y=kv("Sender Address",sender or "N/A",y)
    y=kv("Subject Line",(str(subject)[:80]+"…") if len(str(subject))>80 else (subject or "N/A"),y)
    y=kv("Scan Timestamp",scan_time,y); y=kv("Scanned By",scanned_by,y); y-=10
    y=sec("2.  Threat Assessment",y)
    c.setFont("Helvetica-Bold",38); c.setFillColor(RISK_COL); c.drawString(M,y-18,f"{threat_score:.1f}")
    c.setFont("Helvetica",12); c.setFillColor(LGREY); c.drawString(M+78,y-8,"/ 100")
    c.setFont("Helvetica",8); c.drawString(M+78,y-20,"Composite Threat Score")
    c.setFont("Helvetica-Bold",13); c.setFillColor(RISK_COL); c.drawString(M+200,y-12,f"Risk Level: {risk_level}")
    y-=34
    bw2=W-2*M; c.setStrokeColor(DIV); c.setLineWidth(0.6); c.rect(M,y,bw2,10,fill=0,stroke=1)
    fw=(threat_score/100)*bw2; c.setFillColor(RISK_COL); c.rect(M,y,fw,10,fill=1,stroke=0)
    c.setFont("Helvetica",7); c.setFillColor(LGREY); c.drawRightString(W-M,y-7,f"{threat_score:.1f}%"); y-=22
    y=kv("Phishing Probability",f"{phishing_prob:.2f}%",y,col=colors.HexColor("#CC0000"),bold=True)
    y=kv("Legitimate Probability",f"{legit_prob:.2f}%",y,col=colors.HexColor("#1560FF"),bold=True)
    y=kv("Model Confidence",confidence_label,y,bold=True)
    y=kv("Confidence Index",f"{conf_index:.1f} / 50",y); y-=10
    y=sec("3.  Rule-Based Check Results",y)
    y=chk("ML Classifier",prediction==1,y); y=chk("Suspicious Domain",domain_flag,y)
    y=chk("Phishing Keyword Match",keyword_flag,y); y=chk("Suspicious Link Present",link_flag,y); y-=10
    y=sec("4.  Attack Classification",y)
    atxt=phishing_type if risk_level!="LOW" else "No attack pattern detected"
    acol=colors.HexColor("#CC0000") if risk_level!="LOW" else colors.HexColor("#1560FF")
    y=kv("Identified Threat Type",atxt,y,col=acol,bold=True); y-=10
    y=sec("5.  Recommended Action",y)
    if risk_level=="HIGH":
        lines=["Do NOT interact with this email.","Quarantine immediately and report to IT Security.","Block sender domain. Do not click any links or attachments."]
    elif risk_level=="MEDIUM":
        lines=["Exercise caution before responding.","Verify sender through an independent channel.","Do not click links or download attachments until verified."]
    else:
        lines=["Email appears legitimate based on current scan.","Safe to proceed — continue applying standard email caution."]
    bh=len(lines)*15+14
    c.setFillColor(RISK_COL); c.setFillAlpha(0.05); c.rect(M,y-bh+12,W-2*M,bh,fill=1,stroke=0)
    c.setFillAlpha(1); c.setStrokeColor(RISK_COL); c.setLineWidth(2); c.line(M,y-bh+12,M,y+12)
    for ln in lines:
        c.setFont("Helvetica",9); c.setFillColor(DARK); c.drawString(M+12,y,f"•  {ln}"); y-=15
    c.setStrokeColor(DIV); c.setLineWidth(0.8); c.line(M,34,W-M,34)
    c.setFont("Helvetica",7.5); c.setFillColor(LGREY)
    c.drawString(M,22,"© 2026  Phishing Email Detection System  —  Confidential")
    c.drawRightString(W-M,22,"Page 1 of 1")
    c.save(); buffer.seek(0); return buffer.read()


# ════════════════════════════════════════════════════════════════
#  GLOBAL CSS — FULL CYBERSECURITY THEME
# ════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Exo+2:wght@300;400;500;600;700&display=swap');

:root {
  --bg:       #020817;
  --bg2:      #050D1A;
  --surface:  #0A1628;
  --card:     #0D1F3C;
  --border:   #112240;
  --border2:  #1A3560;
  --blue:     #00A8FF;
  --blue2:    #0066FF;
  --cyan:     #00F5FF;
  --red:      #FF003C;
  --red2:     #FF2D55;
  --orange:   #FF6B00;
  --green:    #00FF88;
  --purple:   #7B2FFF;
  --yellow:   #FFD700;
  --text:     #E2EEFF;
  --muted:    #4A6FA5;
  --dim:      #1A3050;
}

html, body, [class*="css"] {
  background: var(--bg) !important;
  color: var(--text) !important;
  font-family: 'Exo 2', sans-serif !important;
}

/* animated moving grid */
.main {
  background-image:
    linear-gradient(rgba(0,168,255,0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,168,255,0.04) 1px, transparent 1px);
  background-size: 40px 40px;
  animation: bgScroll 25s linear infinite;
}
@keyframes bgScroll {
  0%   { background-position: 0 0; }
  100% { background-position: 40px 40px; }
}

.main .block-container { padding: 0 !important; max-width: 100% !important; }
[data-testid="stSidebar"] { display: none !important; }
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: var(--blue); }

/* ── INPUTS ── */
.stTextInput > div > div > input,
.stTextArea  > div > div > textarea {
  background: var(--surface) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 6px !important;
  color: var(--text) !important;
  font-family: 'Exo 2', sans-serif !important;
  font-size: 0.88rem !important;
  padding: 0.3rem 0.75rem !important;
  transition: all 0.2s !important;
}

.stTextInput > div > div > input:focus,
.stTextArea  > div > div > textarea:focus {
  border-color: var(--blue) !important;
  box-shadow: 0 0 0 2px rgba(0,168,255,0.15), 0 0 18px rgba(0,168,255,0.1) !important;
  background: #071222 !important;
}
.stTextInput label, .stTextArea label {
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.65rem !important;
  font-weight: 500 !important;
  color: var(--muted) !important;
  letter-spacing: 0.12em !important;
  text-transform: uppercase !important;
}

/* ── BUTTONS ── */
.stButton > button {
  background: linear-gradient(135deg, var(--blue2), var(--blue)) !important;
  border: none !important;
  border-radius: 6px !important;
  color: white !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-size: 0.9rem !important;
  font-weight: 700 !important;
  letter-spacing: 0.06em !important;
  padding: 0.6rem 1.3rem !important;
  transition: all 0.2s !important;
  position: relative !important;
  overflow: hidden !important;
}
.stButton > button::before {
  content: "";
  position: absolute; top:0; left:-100%; width:100%; height:100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.12), transparent);
  transition: left 0.45s ease;
}
.stButton > button:hover::before { left: 100%; }
.stButton > button:hover {
  transform: translateY(-1px) !important;
  box-shadow: 0 4px 20px rgba(0,168,255,0.4), 0 0 30px rgba(0,168,255,0.2) !important;
}

/* ── DOWNLOAD BUTTON ── */
.stDownloadButton > button {
  background: transparent !important;
  border: 1px solid var(--cyan) !important;
  border-radius: 6px !important;
  color: var(--cyan) !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-size: 0.88rem !important;
  font-weight: 700 !important;
  letter-spacing: 0.06em !important;
  padding: 0.6rem 1.3rem !important;
  transition: all 0.2s !important;
}
.stDownloadButton > button:hover {
  background: rgba(0,245,255,0.08) !important;
  box-shadow: 0 0 20px rgba(0,245,255,0.25) !important;
  transform: translateY(-1px) !important;
}

/* ── METRICS ── */
[data-testid="stMetric"] {
  background: var(--card) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 10px !important;
  padding: 1.1rem 1.3rem !important;
  position: relative; overflow: hidden;
  transition: transform 0.2s, box-shadow 0.2s;
}
[data-testid="stMetric"]:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 30px rgba(0,168,255,0.15) !important;
}
[data-testid="stMetric"]::before {
  content: "";
  position: absolute; top:0; left:0; right:0; height:2px;
  background: linear-gradient(90deg, var(--blue2), var(--cyan));
}
[data-testid="stMetricValue"] {
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 1.9rem !important;
  font-weight: 600 !important;
  color: var(--cyan) !important;
  text-shadow: 0 0 20px rgba(0,245,255,0.4) !important;
}
[data-testid="stMetricLabel"] {
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.62rem !important;
  color: var(--muted) !important;
  letter-spacing: 0.1em !important;
  text-transform: uppercase !important;
}

/* ── SELECT / MISC ── */
.stSelectbox > div > div {
  background: var(--surface) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 6px !important;
  color: var(--text) !important;
  font-family: 'Exo 2', sans-serif !important;
}
[data-testid="column"] { padding: 0 0.35rem !important; }
h1,h2,h3 { font-family: 'Rajdhani', sans-serif !important; font-weight: 700 !important; color: var(--text) !important; }
.stAlert { border-radius: 8px !important; }
</style>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
#  LOGIN PAGE
# ════════════════════════════════════════════════════════════════
def login_page():
    st.markdown("""
    <style>
    @keyframes bgScroll2 { 0%{background-position:0 0;} 100%{background-position:44px 44px;} }
    @keyframes cardIn2   { from{opacity:0;transform:translateY(24px) scale(0.97);} to{opacity:1;transform:translateY(0) scale(1);} }
    @keyframes shPulse   { 0%,100%{filter:drop-shadow(0 0 14px rgba(0,168,255,0.7));} 50%{filter:drop-shadow(0 0 28px rgba(0,245,255,1)) drop-shadow(0 0 50px rgba(0,102,255,0.6));} }
    @keyframes blink2    { 0%,100%{opacity:1;} 50%{opacity:0.2;} }

    .lbg {
      position:fixed; inset:0; z-index:0;
      background:#020817;
      background-image:
        linear-gradient(rgba(0,168,255,0.035) 1px,transparent 1px),
        linear-gradient(90deg,rgba(0,168,255,0.035) 1px,transparent 1px);
      background-size:44px 44px;
      animation:bgScroll2 28s linear infinite;
    }
    .lbg::before {
      content:""; position:fixed; inset:0; pointer-events:none;
      background:
        radial-gradient(ellipse 60% 50% at 18% 18%, rgba(0,102,255,0.15) 0%,transparent 60%),
        radial-gradient(ellipse 40% 35% at 82% 78%, rgba(123,47,255,0.1) 0%,transparent 60%);
    }
    .lbg::after {
      content:""; position:fixed; top:0; left:0; right:0; height:2px;
      background:linear-gradient(90deg,transparent,#0066FF 30%,#00F5FF 50%,#7B2FFF 70%,transparent);
    }
    .ltopbar {
      position:fixed; top:0; left:0; right:0; height:34px; z-index:100;
      background:rgba(2,8,23,0.95);
      border-bottom:1px solid #0D1F3C;
      display:flex; align-items:center; justify-content:space-between;
      padding:0 2rem;
      font-family:'JetBrains Mono',monospace; font-size:0.56rem;
      letter-spacing:0.12em;
    }
    .ltopbar-l { display:flex; align-items:center; gap:18px; color:#1A3560; }
    .ltopbar-r { color:#1A3560; }
    .ldot {
      width:5px; height:5px; border-radius:50%;
      display:inline-block; margin-right:5px;
      animation:blink2 2s ease-in-out infinite;
    }
    .ldot-g{background:#00FF88;box-shadow:0 0 5px #00FF88;}
    .ldot-b{background:#00A8FF;box-shadow:0 0 5px #00A8FF;animation-delay:.7s;}
    .ldot-p{background:#7B2FFF;box-shadow:0 0 5px #7B2FFF;animation-delay:1.4s;}
    .lshell {
      position:relative; z-index:1;
      min-height:40vh;
      display:flex; align-items:center; justify-content:center;
      padding-top:34px;
      padding-bottom:0;
    }
    .lcard {
      width:420px;
      background:rgba(8,16,32,0.94);
      border:1px solid #1A3560;
      border-radius:16px;
      overflow:hidden;
      box-shadow:0 0 0 1px rgba(0,168,255,0.06), 0 40px 100px rgba(0,0,0,0.8), 0 0 80px rgba(0,102,255,0.07);
      animation:cardIn2 0.5s cubic-bezier(.4,0,.2,1) both;
      backdrop-filter:blur(24px);
    }
    .lcard-top {
      background:linear-gradient(135deg,#050D1A 0%,#0A1628 100%);
      border-bottom:1px solid #1A3560;
      padding:1.8rem 2rem 1.5rem;
      position:relative; overflow:hidden;
    }
    .lcard-top::before {
      content:""; position:absolute; top:0; left:0; right:0; height:3px;
      background:linear-gradient(90deg,#0066FF 0%,#00F5FF 45%,#7B2FFF 80%,#FF003C 100%);
    }
    .lcard-top::after {
      content:""; position:absolute; top:-50px; right:-50px;
      width:140px; height:140px; border-radius:50%;
      background:radial-gradient(circle,rgba(0,168,255,0.1) 0%,transparent 70%);
    }
    .lshield-row { display:flex; align-items:center; gap:14px; position:relative; z-index:1; }
    .lshield { font-size:2.5rem; filter:drop-shadow(0 0 14px rgba(0,168,255,0.7)); animation:shPulse 4s ease-in-out infinite; flex-shrink:0; }
    .lcard-label { font-family:'JetBrains Mono',monospace; font-size:0.56rem; color:#00A8FF; letter-spacing:0.2em; text-transform:uppercase; margin-bottom:4px; }
    .lcard-label::before { content:"// "; color:#FF003C; }
    .lcard-title { font-family:'Rajdhani',sans-serif; font-size:1.2rem; font-weight:700; color:#E2EEFF; line-height:1.2; letter-spacing:0.03em; }
    .lcard-sub   { font-family:'JetBrains Mono',monospace; font-size:0.56rem; color:#2A4A70; letter-spacing:0.1em; margin-top:3px; }
    .lstatus { display:flex; gap:10px; margin-top:0.9rem; position:relative; z-index:1; flex-wrap:wrap; }
    .lpill {
      display:flex; align-items:center; gap:4px;
      background:rgba(0,0,0,0.3); border:1px solid #0D1F3C;
      border-radius:99px; padding:3px 9px;
      font-family:'JetBrains Mono',monospace; font-size:0.53rem;
      letter-spacing:0.08em; white-space:nowrap;
    }
    .lcard-body { padding:1.6rem 2rem 1.8rem; }
    .lfield-lbl {
      font-family:'JetBrains Mono',monospace; font-size:0.58rem;
      color:#4A6FA5; letter-spacing:0.14em; text-transform:uppercase;
      margin-bottom:6px; margin-top:1rem;
    }
    .lfield-lbl::before { content:"▸  "; color:#0066FF; }
    .lcard-foot {
      border-top:1px solid #0D1F3C;
      padding:0.8rem 2rem;
      display:flex; justify-content:space-between; align-items:center;
      background:rgba(2,8,23,0.5);
      font-family:'JetBrains Mono',monospace; font-size:0.53rem;
      color:#0D1F3C; letter-spacing:0.1em;
    }
    </style>

    <div class="lbg"></div>
    <div class="ltopbar">
      <div class="ltopbar-l">
        <span><span class="ldot ldot-g"></span>SYSTEM ONLINE</span>
        <span><span class="ldot ldot-b"></span>ML ENGINE ACTIVE</span>
        <span><span class="ldot ldot-p"></span>THREAT MONITOR</span>
      </div>
      <div class="ltopbar-r">PHISHING EMAIL DETECTION SYSTEM  v3.0</div>
    </div>

    <div class="lshell">
      <div class="lcard">
        <div class="lcard-top">
          <div class="lshield-row">
            <div class="lshield">🛡️</div>
            <div>
              <div class="lcard-label">Cybersecurity Intelligence Platform</div>
              <div class="lcard-title">PHISHING EMAIL<br/>DETECTION SYSTEM</div>
              <div class="lcard-sub">SECURE ACCESS PORTAL · AUTHORIZED USERS ONLY</div>
            </div>
          </div>
          <div class="lstatus">
            <div class="lpill"><span class="ldot ldot-g"></span><span style="color:#00FF88;">ONLINE</span></div>
            <div class="lpill"><span class="ldot ldot-b"></span><span style="color:#00A8FF;">ML READY</span></div>
            <div class="lpill"><span class="ldot ldot-p"></span><span style="color:#7B2FFF;">MONITORING</span></div>
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Form fields pulled tight under the card with negative margin ──
    st.markdown("""
    <style>
    /* Pull the form column tightly under the card */
    .login-form-wrap { margin-top: -18rem !important; }
    </style>
    <div class="login-form-wrap"></div>
    """, unsafe_allow_html=True)

    col_l, col_c, col_r = st.columns([1, 1.36, 1])
    with col_c:
        st.markdown("""<style>
        .stTextInput > div > div > input {
          padding-top: 0.25rem !important;
          padding-bottom: 0.25rem !important;
          font-size: 0.76rem !important;
          min-height: unset !important;
          line-height: 1.3 !important;
        }
        .stTextInput > div > div { min-height: unset !important; }
        </style>""", unsafe_allow_html=True)
        username = st.text_input("Username", placeholder="Enter your username", key="lu")
        password = st.text_input("Password", placeholder="Enter your password",
                                  type="password", key="lp")
        st.markdown("<div style='height:2px'></div>", unsafe_allow_html=True)
        if st.button("⟶  AUTHENTICATE & ACCESS", use_container_width=True):
            if username in USERS and USERS[username]["password"] == password:
                st.session_state.logged_in = True
                st.session_state.username  = username
                st.session_state.page      = "dashboard"
                st.rerun()
            else:
                st.markdown("""
                <div style="background:rgba(255,0,60,0.07);border:1px solid rgba(255,0,60,0.3);
                     border-left:3px solid #FF003C;border-radius:6px;padding:0.7rem 1rem;
                     margin-top:0.5rem;font-family:'JetBrains Mono',monospace;
                     font-size:0.68rem;color:#FF2D55;letter-spacing:0.08em;">
                  ⚠  ACCESS DENIED — Invalid credentials. Please try again.
                </div>""", unsafe_allow_html=True)
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.54rem;
             color:#1A3560;text-align:center;margin-top:1.2rem;letter-spacing:0.12em;">
          © 2026 · PHISHING EMAIL DETECTION SYSTEM · AUTHORIZED ACCESS ONLY
        </div>""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
#  NAVBAR
# ════════════════════════════════════════════════════════════════
def render_navbar():
    user = USERS[st.session_state.username]
    initials = user['name'][0].upper()

    st.markdown(f"""
    <style>
    .navbar {{
      position: sticky; top:0; z-index:999;
      background: rgba(5,13,26,0.97);
      backdrop-filter: blur(16px);
      border-bottom: 1px solid #112240;
      padding: 0.75rem 2rem;
      display: flex; align-items: center; justify-content: space-between;
    }}
    .navbar::after {{
      content: "";
      position: absolute; bottom:0; left:0; right:0; height:1px;
      background: linear-gradient(90deg, transparent, rgba(0,168,255,0.4), rgba(0,245,255,0.4), transparent);
    }}
    .nb-brand {{ display:flex; align-items:center; gap:12px; }}
    .nb-icon {{ font-size:1.5rem; filter: drop-shadow(0 0 10px rgba(0,168,255,0.7)); }}
    .nb-title {{ font-family:'Rajdhani',sans-serif; font-size:1rem; font-weight:700;
      color:#E2EEFF; letter-spacing:0.04em; }}
    .nb-sub {{ font-family:'JetBrains Mono',monospace; font-size:0.58rem;
      color:#4A6FA5; letter-spacing:0.12em; text-transform:uppercase; }}
    .nb-user {{ display:flex; align-items:center; gap:10px; }}
    .nb-avatar {{
      width:34px; height:34px; border-radius:50%;
      background: linear-gradient(135deg, #0066FF, #00F5FF);
      display:flex; align-items:center; justify-content:center;
      font-family:'Rajdhani',sans-serif; font-weight:700; font-size:0.9rem; color:white;
      box-shadow: 0 0 12px rgba(0,168,255,0.4);
    }}
    .nb-name {{ font-family:'Exo 2',sans-serif; font-size:0.82rem; font-weight:600; color:#E2EEFF; }}
    .nb-role {{ font-family:'JetBrains Mono',monospace; font-size:0.6rem; color:#00A8FF; letter-spacing:0.08em; }}
    .online-dot {{
      width:7px; height:7px; border-radius:50%; background:#00FF88;
      box-shadow: 0 0 8px #00FF88; animation: blink 2s infinite;
      display:inline-block; margin-right:4px;
    }}
    </style>
    <div class="navbar">
      <div class="nb-brand">
        <span class="nb-icon">🛡️</span>
        <div>
          <div class="nb-title">Phishing Email Detection System</div>
          <div class="nb-sub">// Cybersecurity Intelligence Platform</div>
        </div>
      </div>
      <div class="nb-user">
        <span class="online-dot"></span>
        <div>
          <div class="nb-name">{user['name']}</div>
          <div class="nb-role">{user['role']}</div>
        </div>
        <div class="nb-avatar">{initials}</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # tab bar
    st.markdown("""
    <div style="background:rgba(5,13,26,0.97);border-bottom:1px solid #112240;
         padding:0.3rem 1.6rem 0; display:flex; gap:4px;">
    </div>
    """, unsafe_allow_html=True)

    pg = st.session_state.page

    def tab_style(name):
        active = pg == name
        if active:
            return ("background:rgba(0,168,255,0.12);color:#00F5FF;"
                    "border-bottom:2px solid #00F5FF;border-radius:6px 6px 0 0;")
        return "color:#4A6FA5;"

    t1,t2,t3,_sp,tlo = st.columns([0.9,0.9,0.9,7,1])
    with t1:
        if st.button("⬡  Dashboard", key="nt1", use_container_width=True):
            st.session_state.page="dashboard"; st.rerun()
    with t2:
        if st.button("⬡  Scan Email", key="nt2", use_container_width=True):
            st.session_state.page="scan"; st.rerun()
    with t3:
        if st.button("⬡  History", key="nt3", use_container_width=True):
            st.session_state.page="history"; st.rerun()
    with tlo:
        if st.button("⎋  Logout", key="ntlo", use_container_width=True):
            st.session_state.logged_in=False; st.session_state.username=""
            st.session_state.last_result=None; st.rerun()

    st.markdown("<div style='height:0.2rem;background:linear-gradient(90deg,transparent,rgba(0,168,255,0.15),transparent);'></div>", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
#  DASHBOARD
# ════════════════════════════════════════════════════════════════
def dashboard_page():
    df    = pd.read_csv(history_file)
    total = len(df)
    legit = len(df[df["risk"]=="LOW"])
    high  = len(df[df["risk"]=="HIGH"])
    med   = len(df[df["risk"]=="MEDIUM"])
    threats = high + med

    st.markdown("""
    <div style="padding:1.8rem 2rem 0.8rem;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:0.3rem;">
        <span style="font-size:1.2rem;filter:drop-shadow(0 0 8px rgba(0,168,255,0.7));">📊</span>
        <span style="font-family:'Rajdhani',sans-serif;font-size:1.6rem;font-weight:700;
              color:#E2EEFF;letter-spacing:0.03em;">Security Dashboard</span>
      </div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
           color:#4A6FA5;letter-spacing:0.1em;">
        // REAL-TIME THREAT INTELLIGENCE OVERVIEW
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='padding:0 1.6rem;'>", unsafe_allow_html=True)

    # stat cards
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("⬡ Total Scans",     total)
    c2.metric("✓ Legitimate",      legit)
    c3.metric("⚠ Threats Caught",  threats)
    c4.metric("🔴 High Risk",      high)
    c5.metric("🟡 Medium Risk",    med)

    st.markdown("<div style='height:1.4rem'></div>", unsafe_allow_html=True)

    left, right = st.columns([1.65, 1])

    # ── LEFT: recent activity ──────────────────────────────────
    with left:
        st.markdown("""
        <div style="background:rgba(10,22,40,0.9);border:1px solid #1A3560;
             border-radius:12px;padding:1.4rem 1.6rem;margin-bottom:1rem;
             position:relative;overflow:hidden;">
          <div style="position:absolute;top:0;left:0;right:0;height:2px;
               background:linear-gradient(90deg,#0066FF,#00F5FF,transparent);"></div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
               font-weight:600;color:#00A8FF;letter-spacing:0.14em;
               text-transform:uppercase;margin-bottom:1rem;">
            ▸ Recent Scan Activity
          </div>
        """, unsafe_allow_html=True)

        if total == 0:
            st.markdown("""<div style='font-family:"JetBrains Mono",monospace;
                font-size:0.75rem;color:#1A3560;padding:1.5rem 0;text-align:center;
                letter-spacing:0.1em;'>NO SCAN RECORDS — AWAITING INPUT</div>""",
                unsafe_allow_html=True)
        else:
            recent = df.tail(10).iloc[::-1]
            for _, row in recent.iterrows():
                rc  = "#FF003C" if row['risk']=="HIGH" else "#FFD700" if row['risk']=="MEDIUM" else "#00FF88"
                dot = "🔴" if row['risk']=="HIGH" else "🟡" if row['risk']=="MEDIUM" else "🟢"
                s_d = str(row.get('sender','N/A'))[:38]
                sub_d = str(row.get('subject','N/A'))[:42]
                t_d = str(row.get('time',''))[:16]
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:12px;
                     padding:0.6rem 0;border-bottom:1px solid #0D1F3C;">
                  <span style="font-size:0.85rem;flex-shrink:0;">{dot}</span>
                  <div style="flex:1;min-width:0;">
                    <div style="font-family:'Exo 2',sans-serif;font-size:0.8rem;font-weight:500;
                         color:#C8DEFF;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                         {s_d}</div>
                    <div style="font-size:0.7rem;color:#4A6FA5;white-space:nowrap;
                         overflow:hidden;text-overflow:ellipsis;">{sub_d}</div>
                  </div>
                  <div style="text-align:right;flex-shrink:0;">
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;
                         font-weight:700;color:{rc};">{row['risk']}</div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                         color:#2A4A70;">{t_d}</div>
                  </div>
                </div>""", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    # ── RIGHT: breakdown + quick scan ─────────────────────────
    with right:
        st.markdown("""
        <div style="background:rgba(10,22,40,0.9);border:1px solid #1A3560;
             border-radius:12px;padding:1.4rem 1.6rem;margin-bottom:1rem;
             position:relative;overflow:hidden;">
          <div style="position:absolute;top:0;left:0;right:0;height:2px;
               background:linear-gradient(90deg,#FF003C,#FF6B00,transparent);"></div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
               font-weight:600;color:#FF2D55;letter-spacing:0.14em;
               text-transform:uppercase;margin-bottom:1rem;">
            ▸ Threat Breakdown
          </div>
        """, unsafe_allow_html=True)

        if total > 0:
            for label, count, col, glow in [
                ("High Risk",   high,   "#FF003C", "rgba(255,0,60,0.4)"),
                ("Medium Risk", med,    "#FFD700", "rgba(255,215,0,0.4)"),
                ("Legitimate",  legit,  "#00FF88", "rgba(0,255,136,0.4)"),
            ]:
                pct = (count/total)*100
                st.markdown(f"""
                <div style="margin-bottom:1rem;">
                  <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
                    <span style="font-family:'Exo 2',sans-serif;font-size:0.78rem;
                          color:#8AABCC;">{label}</span>
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                          font-weight:600;color:{col};">{count} ({pct:.0f}%)</span>
                  </div>
                  <div style="background:#071222;border:1px solid #112240;
                       border-radius:99px;height:6px;overflow:hidden;">
                    <div style="width:{pct}%;height:6px;background:{col};
                         border-radius:99px;box-shadow:0 0 8px {glow};
                         transition:width 0.8s ease;"></div>
                  </div>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown("<div style='font-family:\"JetBrains Mono\",monospace;font-size:0.72rem;color:#1A3560;'>NO DATA</div>", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

        # quick scan card
        st.markdown("""
        <div style="background:rgba(0,102,255,0.07);border:1px solid rgba(0,168,255,0.25);
             border-radius:12px;padding:1.3rem 1.5rem;position:relative;overflow:hidden;">
          <div style="position:absolute;top:0;left:0;right:0;height:2px;
               background:linear-gradient(90deg,#0066FF,#00F5FF);"></div>
          <div style="font-family:'Rajdhani',sans-serif;font-size:1rem;font-weight:700;
               color:#E2EEFF;margin-bottom:0.3rem;">🔍 Run a New Scan</div>
          <div style="font-family:'Exo 2',sans-serif;font-size:0.76rem;color:#4A6FA5;
               margin-bottom:0.9rem;">Analyze an email for phishing threats in seconds.</div>
        """, unsafe_allow_html=True)
        if st.button("⟶  Go to Scan Email", key="dash_scan", use_container_width=True):
            st.session_state.page="scan"; st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
#  SCAN PAGE
# ════════════════════════════════════════════════════════════════
def scan_page():
    st.markdown("""
    <div style="padding:1.8rem 2rem 0.8rem;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:0.3rem;">
        <span style="font-size:1.2rem;filter:drop-shadow(0 0 8px rgba(0,245,255,0.7));">🔍</span>
        <span style="font-family:'Rajdhani',sans-serif;font-size:1.6rem;font-weight:700;
              color:#E2EEFF;letter-spacing:0.03em;">Scan Email</span>
      </div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
           color:#4A6FA5;letter-spacing:0.1em;">
        // ML + RULE-BASED THREAT ANALYSIS ENGINE
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='padding:0 1.6rem;'>", unsafe_allow_html=True)
    form_col, res_col = st.columns([1, 1.1])

    with form_col:
        st.markdown("""
        <div style="background:rgba(10,22,40,0.9);border:1px solid #1A3560;
             border-radius:12px;padding:1.6rem 1.8rem;position:relative;overflow:hidden;">
          <div style="position:absolute;top:0;left:0;right:0;height:2px;
               background:linear-gradient(90deg,#0066FF,#00F5FF,#7B2FFF,transparent);"></div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
               font-weight:600;color:#00A8FF;letter-spacing:0.16em;
               text-transform:uppercase;margin-bottom:1.2rem;">▸ Email Input Console</div>
        """, unsafe_allow_html=True)

        sender  = st.text_input("Sender Email",  placeholder="attacker@suspicious-domain.net", key="ss")
        subject = st.text_input("Subject",       placeholder="Enter email subject",             key="sq")
        body    = st.text_area( "Email Body",    placeholder="Paste full email body here...",
                                height=195, key="sb")

        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
        scan_btn = st.button("⟶  INITIATE SECURITY SCAN", use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with res_col:
        if scan_btn:
            combined      = subject + " " + body
            vec           = vectorizer.transform([combined])
            prediction    = model.predict(vec)[0]
            prob          = model.predict_proba(vec)[0]
            phishing_prob = prob[1]*100
            legit_prob    = prob[0]*100

            # ── Rule-based checks via utils.py ──────────────────
            domain_flag  = check_suspicious_domain(sender)
            keyword_flag = check_suspicious_keywords(combined)
            link_flag    = check_suspicious_links(combined)

            # ── Scoring & classification via utils.py ────────────
            score          = calculate_threat_score(phishing_prob, domain_flag, keyword_flag, link_flag)
            risk           = classify_risk_level(score)
            now            = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conf_label, conf = get_confidence_label(phishing_prob)
            ptype          = classify_attack_type(combined, keyword_flag)

            df_h = pd.read_csv(history_file)
            pd.concat([df_h, pd.DataFrame([{
                "time":now,"sender":sender,"subject":subject,"risk":risk,"score":score,
                "phishing_prob":phishing_prob,"legit_prob":legit_prob,
                "prediction":int(prediction),"domain_flag":int(domain_flag),
                "keyword_flag":int(keyword_flag),"link_flag":int(link_flag),
                "ptype":ptype,"conf_label":conf_label,"conf":round(conf,2)
            }])], ignore_index=True).to_csv(history_file, index=False)

            st.session_state.last_result = dict(
                sender=sender, subject=subject, risk=risk, score=score,
                phishing_prob=phishing_prob, legit_prob=legit_prob,
                prediction=prediction, domain_flag=domain_flag,
                keyword_flag=keyword_flag, link_flag=link_flag,
                ptype=ptype, now=now, conf_label=conf_label, conf=conf
            )

        r = st.session_state.last_result
        if r:
            risk  = r["risk"]
            score = r["score"]
            rc    = "#FF003C" if risk=="HIGH" else "#FFD700" if risk=="MEDIUM" else "#00FF88"
            rbg   = "rgba(255,0,60,0.07)"   if risk=="HIGH" else \
                    "rgba(255,215,0,0.07)"  if risk=="MEDIUM" else "rgba(0,255,136,0.07)"
            rb    = "rgba(255,0,60,0.4)"    if risk=="HIGH" else \
                    "rgba(255,215,0,0.4)"   if risk=="MEDIUM" else "rgba(0,255,136,0.4)"
            icon  = "🔴" if risk=="HIGH" else "🟡" if risk=="MEDIUM" else "🟢"
            verd  = "HIGH RISK — Phishing Detected" if risk=="HIGH" else \
                    "MEDIUM RISK — Suspicious Email" if risk=="MEDIUM" else \
                    "LOW RISK — Email Appears Legitimate"

            st.markdown(f"""
            <div style="background:rgba(10,22,40,0.9);border:1px solid #1A3560;
                 border-radius:12px;padding:1.6rem 1.8rem;position:relative;overflow:hidden;">
              <div style="position:absolute;top:0;left:0;right:0;height:2px;
                   background:linear-gradient(90deg,{rc},{rc}66,transparent);"></div>

              <!-- verdict -->
              <div style="background:{rbg};border:1px solid {rb};border-left:3px solid {rc};
                   border-radius:8px;padding:1rem 1.2rem;margin-bottom:1.4rem;">
                <div style="font-family:'Rajdhani',sans-serif;font-size:1.15rem;font-weight:700;
                     color:{rc};letter-spacing:0.04em;">{icon}  {verd}</div>
              </div>

              <!-- score -->
              <div style="display:flex;align-items:flex-end;gap:16px;margin-bottom:1.2rem;">
                <div>
                  <div style="font-family:'JetBrains Mono',monospace;font-size:3.2rem;
                       font-weight:600;color:{rc};line-height:1;
                       text-shadow:0 0 30px {rc}88;">{score:.1f}</div>
                  <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                       color:#4A6FA5;margin-top:3px;letter-spacing:0.1em;">THREAT SCORE / 100</div>
                </div>
                <div style="flex:1;padding-bottom:0.6rem;">
                  <div style="background:#071222;border:1px solid #112240;
                       border-radius:99px;height:8px;overflow:hidden;">
                    <div style="width:{score}%;height:8px;border-radius:99px;
                         background:linear-gradient(90deg,{rc},{rc}88);
                         box-shadow:0 0 12px {rc}66;"></div>
                  </div>
                </div>
              </div>

              <!-- prob -->
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:1.1rem;">
                <div style="background:#071222;border:1px solid #112240;border-radius:8px;padding:0.8rem 0.9rem;">
                  <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                       color:#4A6FA5;letter-spacing:0.1em;margin-bottom:4px;">PHISHING PROB</div>
                  <div style="font-family:'JetBrains Mono',monospace;font-size:1.3rem;
                       font-weight:600;color:#FF2D55;text-shadow:0 0 12px rgba(255,45,85,0.5);">
                    {r['phishing_prob']:.1f}%</div>
                </div>
                <div style="background:#071222;border:1px solid #112240;border-radius:8px;padding:0.8rem 0.9rem;">
                  <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                       color:#4A6FA5;letter-spacing:0.1em;margin-bottom:4px;">LEGIT PROB</div>
                  <div style="font-family:'JetBrains Mono',monospace;font-size:1.3rem;
                       font-weight:600;color:#00FF88;text-shadow:0 0 12px rgba(0,255,136,0.5);">
                    {r['legit_prob']:.1f}%</div>
                </div>
              </div>

              <!-- indicators -->
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                   color:#4A6FA5;letter-spacing:0.12em;text-transform:uppercase;
                   margin-bottom:0.6rem;">▸ Detection Indicators</div>
              <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:1.1rem;">
            """, unsafe_allow_html=True)

            chips = []
            if r["prediction"]==1: chips.append(("#FF003C","⬡ ML Flagged"))
            if r["domain_flag"]:   chips.append(("#FF003C","⬡ Suspicious Domain"))
            if r["keyword_flag"]:  chips.append(("#FFD700","⬡ Phishing Keywords"))
            if r["link_flag"]:     chips.append(("#FF6B00","⬡ Suspicious Links"))
            if not chips:          chips.append(("#00FF88","✓ No Threats Found"))

            chip_html = ""
            for col, lbl in chips:
                chip_html += f"""<span style="background:{col}15;border:1px solid {col}44;
                    border-radius:5px;padding:3px 10px;font-family:'JetBrains Mono',monospace;
                    font-size:0.65rem;font-weight:600;color:{col};
                    text-shadow:0 0 8px {col}66;">{lbl}</span>"""
            st.markdown(chip_html, unsafe_allow_html=True)

            atk_col = "#FF003C" if risk!="LOW" else "#00FF88"
            atk_txt = r['ptype'] if risk!="LOW" else "None Detected"
            conf_col = "#00A8FF" if r['conf_label']=="HIGH" else "#7B2FFF" if r['conf_label']=="MODERATE" else "#FF003C"

            st.markdown(f"""
              </div>
              <!-- confidence + attack -->
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                <div style="background:#071222;border:1px solid #112240;border-radius:8px;padding:0.8rem 0.9rem;">
                  <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                       color:#4A6FA5;letter-spacing:0.1em;margin-bottom:4px;">MODEL CONFIDENCE</div>
                  <div style="font-family:'Rajdhani',sans-serif;font-size:1.1rem;font-weight:700;
                       color:{conf_col};text-shadow:0 0 10px {conf_col}88;">{r['conf_label']}</div>
                  <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                       color:#2A4A70;margin-top:2px;">INDEX: {r['conf']:.1f} / 50</div>
                </div>
                <div style="background:#071222;border:1px solid #112240;border-radius:8px;padding:0.8rem 0.9rem;">
                  <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                       color:#4A6FA5;letter-spacing:0.1em;margin-bottom:4px;">ATTACK TYPE</div>
                  <div style="font-family:'Rajdhani',sans-serif;font-size:0.88rem;font-weight:700;
                       color:{atk_col};">{atk_txt}</div>
                </div>
              </div>
            </div>
            """, unsafe_allow_html=True)

            # PDF
            st.markdown("<div style='height:0.6rem'></div>", unsafe_allow_html=True)
            if REPORTLAB_AVAILABLE:
                pdf = generate_pdf_report(
                    sender=r["sender"], subject=r["subject"], risk_level=risk,
                    threat_score=score, phishing_prob=r["phishing_prob"],
                    legit_prob=r["legit_prob"], prediction=r["prediction"],
                    domain_flag=r["domain_flag"], keyword_flag=r["keyword_flag"],
                    link_flag=r["link_flag"], phishing_type=r["ptype"],
                    scan_time=r["now"], confidence_label=r["conf_label"],
                    conf_index=r["conf"],
                    scanned_by=USERS[st.session_state.username]["name"]
                )
                fname = f"PhishReport_{risk}_{r['now'].replace(':','-').replace(' ','_')}.pdf"
                st.download_button("⬇  Download PDF Report", data=pdf,
                                   file_name=fname, mime="application/pdf",
                                   use_container_width=True)
            else:
                st.markdown("""<div style="background:rgba(255,107,0,0.07);border:1px solid
                    rgba(255,107,0,0.3);border-left:3px solid #FF6B00;border-radius:6px;
                    padding:0.7rem 1rem;font-family:'JetBrains Mono',monospace;
                    font-size:0.68rem;color:#FF6B00;">
                    ⚠ pip install reportlab &nbsp;to enable PDF export
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background:rgba(10,22,40,0.9);border:1px solid #1A3560;
                 border-radius:12px;padding:3.5rem 2rem;text-align:center;
                 position:relative;overflow:hidden;">
              <div style="position:absolute;top:0;left:0;right:0;height:2px;
                   background:linear-gradient(90deg,transparent,rgba(0,168,255,0.3),transparent);"></div>
              <div style="font-size:3rem;margin-bottom:1rem;
                   filter:drop-shadow(0 0 20px rgba(0,168,255,0.3));opacity:0.4;">🛡️</div>
              <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                   color:#1A3560;letter-spacing:0.14em;">AWAITING SCAN INPUT</div>
              <div style="font-family:'Exo 2',sans-serif;font-size:0.78rem;
                   color:#2A4A70;margin-top:0.5rem;">
                Fill in the email details and click Initiate Security Scan
              </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
#  HISTORY PAGE
# ════════════════════════════════════════════════════════════════
def history_page():
    st.markdown("""
    <div style="padding:1.8rem 2rem 0.8rem;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:0.3rem;">
        <span style="font-size:1.2rem;filter:drop-shadow(0 0 8px rgba(123,47,255,0.7));">📋</span>
        <span style="font-family:'Rajdhani',sans-serif;font-size:1.6rem;font-weight:700;
              color:#E2EEFF;letter-spacing:0.03em;">Scan History</span>
      </div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
           color:#4A6FA5;letter-spacing:0.1em;">// COMPLETE SCAN AUDIT LOG — CLICK ANY ROW TO VIEW FULL REPORT</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='padding:0 1.6rem;'>", unsafe_allow_html=True)

    df = pd.read_csv(history_file)

    bar_l, bar_m, bar_r = st.columns([2, 4, 1.4])
    with bar_l:
        filt = st.selectbox("", ["All","HIGH","MEDIUM","LOW"],
                            key="hf", label_visibility="collapsed")
    with bar_r:
        if st.button("🗑  Clear History", use_container_width=True, key="clr"):
            pd.DataFrame(columns=["time","sender","subject","risk","score",
                "phishing_prob","legit_prob","prediction","domain_flag",
                "keyword_flag","link_flag","ptype","conf_label","conf"]
            ).to_csv(history_file, index=False)
            st.session_state.history = []
            st.rerun()

    if filt != "All":
        df = df[df["risk"]==filt]

    df = df.reset_index(drop=True)
    st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)

    if len(df) == 0:
        st.markdown("""
        <div style="background:rgba(10,22,40,0.9);border:1px solid #1A3560;
             border-radius:12px;padding:3rem;text-align:center;">
          <div style="font-size:2rem;opacity:0.15;margin-bottom:0.8rem;">📋</div>
          <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
               color:#1A3560;letter-spacing:0.14em;">NO SCAN RECORDS FOUND</div>
        </div>""", unsafe_allow_html=True)
    else:
        # show table + expandable report rows
        st.markdown("""
        <div style="background:rgba(10,22,40,0.9);border:1px solid #1A3560;
             border-radius:12px;overflow:hidden;position:relative;">
          <div style="position:absolute;top:0;left:0;right:0;height:2px;
               background:linear-gradient(90deg,#7B2FFF,#00A8FF,#00F5FF,transparent);"></div>
          <div style="display:grid;grid-template-columns:0.3fr 1.4fr 2fr 2fr 100px 85px;
               padding:0.75rem 1.2rem;border-bottom:1px solid #112240;
               font-family:'JetBrains Mono',monospace;font-size:0.58rem;font-weight:600;
               color:#4A6FA5;text-transform:uppercase;letter-spacing:0.12em;">
            <div>#</div><div>Timestamp</div><div>Sender</div><div>Subject</div>
            <div style="text-align:center;">Risk</div>
            <div style="text-align:right;">Score</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        reversed_df = df.iloc[::-1].reset_index(drop=True)

        for i, row in reversed_df.iterrows():
            rc   = "#FF003C" if row["risk"]=="HIGH" else "#FFD700" if row["risk"]=="MEDIUM" else "#00FF88"
            rbg  = f"{rc}0D"
            snd  = str(row.get("sender",""))[:32]
            sub  = str(row.get("subject",""))[:38]
            tme  = str(row.get("time",""))[:16]
            scr  = float(row.get("score", 0))
            num  = len(reversed_df) - i

            st.markdown(f"""
            <div style="background:rgba(10,22,40,0.9);border:1px solid #1A3560;
                 border-top:none;{'border-radius:0 0 12px 12px;' if i==len(reversed_df)-1 else ''}
                 overflow:hidden;">
              <div style="display:grid;grid-template-columns:0.3fr 1.4fr 2fr 2fr 100px 85px;
                   padding:0.68rem 1.2rem;border-bottom:1px solid #071222;
                   font-size:0.8rem;background:transparent;transition:background 0.15s;"
                   onmouseover="this.style.background='rgba(0,168,255,0.035)'"
                   onmouseout="this.style.background='transparent'">
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;color:#1A3560;">{num}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;color:#2A4A70;">{tme}</div>
                <div style="font-family:'Exo 2',sans-serif;color:#C8DEFF;font-size:0.78rem;
                     white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{snd}</div>
                <div style="font-family:'Exo 2',sans-serif;color:#4A6FA5;font-size:0.78rem;
                     white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{sub}</div>
                <div style="text-align:center;">
                  <span style="background:{rbg};border:1px solid {rc}44;border-radius:5px;
                       padding:2px 8px;font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                       font-weight:700;color:{rc};text-shadow:0 0 8px {rc}55;">
                    {row["risk"]}
                  </span>
                </div>
                <div style="text-align:right;font-family:'JetBrains Mono',monospace;
                     font-size:0.7rem;font-weight:600;color:{rc};text-shadow:0 0 6px {rc}44;">
                     {scr:.1f}</div>
              </div>
            </div>
            """, unsafe_allow_html=True)

            # ── Expandable report panel for each row ──────────────
            has_full = "phishing_prob" in row and pd.notna(row.get("phishing_prob"))
            with st.expander(f"  ▸  View Report — Scan #{num}  ({tme})", expanded=False):
                if has_full:
                    pp    = float(row.get("phishing_prob", 0))
                    lp    = float(row.get("legit_prob", 0))
                    pred  = int(float(row.get("prediction", 0)))
                    df_fl = bool(int(float(row.get("domain_flag", 0))))
                    kw_fl = bool(int(float(row.get("keyword_flag", 0))))
                    lk_fl = bool(int(float(row.get("link_flag", 0))))
                    ptype = str(row.get("ptype","General Email Phishing"))
                    cl    = str(row.get("conf_label","N/A"))
                    conf  = float(row.get("conf", 0))
                    r_time= str(row.get("time",""))

                    conf_col = "#00A8FF" if cl=="HIGH" else "#7B2FFF" if cl=="MODERATE" else "#FF003C"
                    atk_col  = "#FF003C" if row["risk"]!="LOW" else "#00FF88"

                    chips = []
                    if pred==1:  chips.append(("#FF003C","⬡ ML Flagged"))
                    if df_fl:    chips.append(("#FF003C","⬡ Suspicious Domain"))
                    if kw_fl:    chips.append(("#FFD700","⬡ Phishing Keywords"))
                    if lk_fl:    chips.append(("#FF6B00","⬡ Suspicious Links"))
                    if not chips:chips.append(("#00FF88","✓ No Threats Found"))
                    chip_html = "".join([
                        f'<span style="background:{c}15;border:1px solid {c}44;border-radius:5px;'
                        f'padding:3px 9px;font-family:JetBrains Mono,monospace;font-size:0.63rem;'
                        f'font-weight:600;color:{c};margin-right:5px;text-shadow:0 0 6px {c}55;">{l}</span>'
                        for c,l in chips
                    ])

                    c1, c2, c3 = st.columns(3)
                    c1.metric("Threat Score", f"{scr:.1f} / 100")
                    c2.metric("Risk Level",   row["risk"])
                    c3.metric("Confidence",   cl)

                    st.markdown(f"""
                    <div style="background:#071222;border:1px solid #112240;border-radius:10px;
                         padding:1.2rem 1.4rem;margin:0.8rem 0;">

                      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:1rem;">
                        <div style="background:#020817;border:1px solid #0D1F3C;border-radius:8px;padding:0.8rem 1rem;">
                          <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                               color:#4A6FA5;letter-spacing:0.1em;margin-bottom:3px;">PHISHING PROBABILITY</div>
                          <div style="font-family:'JetBrains Mono',monospace;font-size:1.4rem;
                               font-weight:600;color:#FF2D55;text-shadow:0 0 12px rgba(255,45,85,0.4);">{pp:.1f}%</div>
                        </div>
                        <div style="background:#020817;border:1px solid #0D1F3C;border-radius:8px;padding:0.8rem 1rem;">
                          <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                               color:#4A6FA5;letter-spacing:0.1em;margin-bottom:3px;">LEGITIMATE PROBABILITY</div>
                          <div style="font-family:'JetBrains Mono',monospace;font-size:1.4rem;
                               font-weight:600;color:#00FF88;text-shadow:0 0 12px rgba(0,255,136,0.4);">{lp:.1f}%</div>
                        </div>
                      </div>

                      <div style="margin-bottom:0.8rem;">
                        <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                             color:#4A6FA5;letter-spacing:0.1em;margin-bottom:6px;">DETECTION INDICATORS</div>
                        <div>{chip_html}</div>
                      </div>

                      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;">
                        <div style="background:#020817;border:1px solid #0D1F3C;border-radius:8px;padding:0.7rem 0.9rem;">
                          <div style="font-family:'JetBrains Mono',monospace;font-size:0.56rem;
                               color:#4A6FA5;letter-spacing:0.1em;margin-bottom:3px;">MODEL CONFIDENCE</div>
                          <div style="font-family:'Rajdhani',sans-serif;font-size:0.95rem;
                               font-weight:700;color:{conf_col};">{cl}</div>
                          <div style="font-family:'JetBrains Mono',monospace;font-size:0.56rem;
                               color:#1A3560;margin-top:2px;">INDEX: {conf:.1f}/50</div>
                        </div>
                        <div style="background:#020817;border:1px solid #0D1F3C;border-radius:8px;padding:0.7rem 0.9rem;">
                          <div style="font-family:'JetBrains Mono',monospace;font-size:0.56rem;
                               color:#4A6FA5;letter-spacing:0.1em;margin-bottom:3px;">ATTACK TYPE</div>
                          <div style="font-family:'Rajdhani',sans-serif;font-size:0.88rem;
                               font-weight:700;color:{atk_col};">{ptype}</div>
                        </div>
                        <div style="background:#020817;border:1px solid #0D1F3C;border-radius:8px;padding:0.7rem 0.9rem;">
                          <div style="font-family:'JetBrains Mono',monospace;font-size:0.56rem;
                               color:#4A6FA5;letter-spacing:0.1em;margin-bottom:3px;">SCAN TIME</div>
                          <div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;
                               color:#C8DEFF;">{r_time}</div>
                        </div>
                      </div>

                    </div>
                    """, unsafe_allow_html=True)

                    # PDF download for this historical scan
                    if REPORTLAB_AVAILABLE:
                        pdf = generate_pdf_report(
                            sender=str(row.get("sender","")),
                            subject=str(row.get("subject","")),
                            risk_level=row["risk"], threat_score=scr,
                            phishing_prob=pp, legit_prob=lp,
                            prediction=pred, domain_flag=df_fl,
                            keyword_flag=kw_fl, link_flag=lk_fl,
                            phishing_type=ptype, scan_time=r_time,
                            confidence_label=cl, conf_index=conf,
                            scanned_by="Historical Record"
                        )
                        fname = f"PhishReport_#{num}_{row['risk']}_{r_time[:10]}.pdf"
                        st.download_button(
                            f"⬇  Download PDF Report — Scan #{num}",
                            data=pdf, file_name=fname,
                            mime="application/pdf",
                            use_container_width=True,
                            key=f"pdf_hist_{i}"
                        )
                else:
                    st.markdown("""
                    <div style="background:#071222;border:1px solid #112240;border-radius:8px;
                         padding:1rem 1.2rem;font-family:'JetBrains Mono',monospace;
                         font-size:0.68rem;color:#2A4A70;letter-spacing:0.08em;">
                      ℹ This scan was recorded before detailed data storage was enabled.
                      Only basic risk and score data is available.
                    </div>""", unsafe_allow_html=True)
                    st.metric("Risk", row["risk"])
                    st.metric("Score", f"{scr:.1f}")

        st.markdown(f"""<div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
             color:#1A3560;margin-top:0.6rem;letter-spacing:0.1em;padding:0 0.2rem;">
             // SHOWING {len(df)} RECORD(S) &nbsp;·&nbsp; CLICK ROW EXPANDER TO VIEW FULL REPORT</div>""",
             unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════
#  ROUTER
# ════════════════════════════════════════════════════════════════
if not st.session_state.logged_in:
    login_page()
else:
    render_navbar()
    pg = st.session_state.page
    if   pg == "dashboard": dashboard_page()
    elif pg == "scan":      scan_page()
    elif pg == "history":   history_page()
    else:                   dashboard_page()
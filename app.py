import hashlib
import hmac
import io
import os
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from backend import load_model, predict_message, predict_messages

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "spamshield.db"

st.set_page_config(page_title="SpamShield | SMS & Email Detection", page_icon="🛡️", layout="wide")


def get_message_signals(message: str):
    text = (message or "").lower()
    signals = []
    keywords = {
        "Prize / giveaway lure": ["winner", "free prize", "claim now", "congratulations", "cash bonus", "lottery", "gift card"],
        "Urgent call-to-action": ["urgent", "act now", "immediately", "today only", "limited time", "expires", "hurry"],
        "Link-driven scam": ["click here", "tap link", "visit now", "open link", "http://", "https://", "www."],
        "Credential request": ["password", "otp", "one-time password", "verify account", "bank details", "update your profile"],
        "Financial pressure": ["invoice", "refund", "payment", "wire transfer", "tax refund", "bank account"],
    }

    for label, terms in keywords.items():
        if any(term in text for term in terms):
            signals.append(label)

    if any(char.isdigit() for char in message) and len(message) > 20:
        signals.append("Heavy numeric content")
    if sum(1 for char in message if char.isupper()) > max(8, len(message) * 0.2):
        signals.append("All-caps emphasis")
    if not signals:
        signals.append("No obvious spam markers")
    return signals[:4]


def render_prediction_card(message: str, label: str, confidence: float):
    is_spam = label == "spam"
    badge = "🚨 Spam risk" if is_spam else "✅ Safe message"
    title = "Likely SPAM" if is_spam else "Likely NOT SPAM"
    action = "Avoid clicking links or sharing credentials." if is_spam else "This message appears legitimate." 
    signals = get_message_signals(message)
    pills = "".join(f"<span class='pill'>{signal}</span>" for signal in signals)

    st.markdown(
        f"""
        <div class="status-card {'spam' if is_spam else 'safe'}">
            <div class="status-top">
                <div class="status-badge">{badge}</div>
                <div class="status-score">{confidence:.1%}</div>
            </div>
            <div class="status-title">{title}</div>
            <div class="status-body">{action}</div>
            <div class="signal-row">{pills}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"pbkdf2_sha256${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False
    if not stored_hash.startswith("pbkdf2_sha256$"):
        return stored_hash == password

    try:
        _, salt_hex, expected_hex = stored_hash.split("$", 2)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(actual, expected)
    except ValueError:
        return False


def ensure_storage():
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            timestamp TEXT,
            text TEXT,
            label TEXT,
            confidence REAL
        )
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        ("admin", hash_password("admin123")),
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
        ("user", hash_password("user123")),
    )
    conn.commit()
    conn.close()


@st.cache_resource
def get_model():
    return load_model()


def load_users():
    ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT username, password FROM users ORDER BY username").fetchall()
    conn.close()
    return {username: password for username, password in rows}


def save_user(username, password):
    ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)",
        (username, hash_password(password)),
    )
    conn.commit()
    conn.close()


def load_saved_history(username=None):
    ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    if username:
        rows = conn.execute(
            """
            SELECT timestamp, username, text, label, confidence
            FROM history
            WHERE username = ?
            ORDER BY id DESC
            LIMIT 20
            """,
            (username,),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT timestamp, username, text, label, confidence
            FROM history
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()
    conn.close()
    return [
        {
            "timestamp": timestamp,
            "user": user,
            "text": text,
            "label": label,
            "confidence": float(confidence),
        }
        for timestamp, user, text, label, confidence in rows
    ]


def save_history(records, username):
    ensure_storage()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM history WHERE username = ?", (username,))
    for record in records:
        conn.execute(
            """
            INSERT INTO history (username, timestamp, text, label, confidence)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                record.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                record.get("text", ""),
                record.get("label", "ham"),
                float(record.get("confidence", 0.0)),
            ),
        )
    conn.commit()
    conn.close()


if "history" not in st.session_state:
    st.session_state.history = []

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = ""


def add_to_history(entry):
    if not st.session_state.user:
        st.session_state.user = "user"

    entry["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry["user"] = st.session_state.user
    st.session_state.history.insert(0, entry)
    st.session_state.history = st.session_state.history[:20]
    save_history(st.session_state.history, st.session_state.user)


def parse_uploaded_messages(uploaded_file):
    if uploaded_file is None:
        return []

    suffix = uploaded_file.name.lower()
    raw = uploaded_file.read()
    uploaded_file.seek(0)
    content = raw.decode("utf-8", errors="ignore")

    if suffix.endswith(".csv"):
        try:
            df = pd.read_csv(io.BytesIO(raw))
            if "text" in df.columns:
                return df["text"].dropna().astype(str).tolist()
            if df.shape[1] > 0:
                return df.iloc[:, 0].dropna().astype(str).tolist()
        except Exception:
            pass

    return [line.strip() for line in content.splitlines() if line.strip()]


def parse_uploaded_messages(uploaded_file):
    if uploaded_file is None:
        return []

    suffix = uploaded_file.name.lower()
    raw = uploaded_file.read()
    uploaded_file.seek(0)
    content = raw.decode("utf-8", errors="ignore")

    if suffix.endswith(".csv"):
        try:
            df = pd.read_csv(io.BytesIO(raw))
            if "text" in df.columns:
                return df["text"].dropna().astype(str).tolist()
            if df.shape[1] > 0:
                return df.iloc[:, 0].dropna().astype(str).tolist()
        except Exception:
            pass

    return [line.strip() for line in content.splitlines() if line.strip()]


st.markdown(
    """
    <style>
        .stApp {
            background: linear-gradient(135deg, #f5f7ff 0%, #eef5ff 100%);
        }
        .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        .hero {
            padding: 1.7rem 1.8rem;
            border-radius: 24px;
            color: white;
            background: linear-gradient(120deg, #0f172a, #1d4ed8 55%, #2563eb);
            margin-bottom: 1.2rem;
            box-shadow: 0 12px 24px rgba(37, 99, 235, 0.18);
        }
        .hero h1 {
            font-size: 2.4rem;
            margin: 0;
            letter-spacing: -0.04em;
        }
        .hero p {
            opacity: 0.9;
            margin-bottom: 0;
            font-size: 1rem;
        }
        .status-card {
            border-radius: 18px;
            padding: 1rem 1.15rem;
            margin-top: 0.9rem;
            box-shadow: 0 12px 24px rgba(15, 23, 42, 0.08);
        }
        .status-card.safe {
            background: linear-gradient(180deg, #ecfdf5, #f0fdf4);
            border: 1px solid #86efac;
            color: #14532d;
        }
        .status-card.spam {
            background: linear-gradient(180deg, #fff1f2, #ffe4e6);
            border: 1px solid #fda4af;
            color: #881337;
        }
        .status-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 0.8rem;
        }
        .status-badge {
            font-weight: 700;
            font-size: 0.8rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }
        .status-score {
            font-weight: 700;
            font-size: 1.2rem;
        }
        .status-title {
            margin-top: 0.5rem;
            font-weight: 800;
            font-size: 1.3rem;
        }
        .status-body {
            margin-top: 0.3rem;
            font-size: 0.96rem;
            opacity: 0.9;
        }
        .signal-row {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.8rem;
        }
        .pill {
            background: rgba(255,255,255,0.7);
            border: 1px solid rgba(15,23,42,0.08);
            border-radius: 999px;
            padding: 0.28rem 0.65rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .result {
            padding: 1rem 1.2rem;
            border-radius: 16px;
            margin-top: 0.8rem;
            font-size: 1.1rem;
            box-shadow: 0 8px 20px rgba(15, 23, 42, 0.06);
        }
        .safe {
            background: #ecfdf5;
            border: 1px solid #86efac;
            color: #14532d;
        }
        .spam {
            background: #fff1f2;
            border: 1px solid #fda4af;
            color: #881337;
        }
        .glass-panel {
            background: rgba(255,255,255,0.78);
            border: 1px solid rgba(148,163,184,0.24);
            border-radius: 18px;
            padding: 1rem 1.1rem;
            box-shadow: 0 10px 22px rgba(15, 23, 42, 0.06);
        }
        div[data-testid="stMetric"] {
            background: linear-gradient(180deg, #ffffff, #f9fbff);
            padding: 1rem 1.1rem;
            border-radius: 16px;
            border: 1px solid rgba(148, 163, 184, 0.3);
            box-shadow: 0 8px 18px rgba(15, 23, 42, 0.06);
        }
        div[data-testid="stForm"] {
            background: rgba(255, 255, 255, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 18px;
            padding: 1rem 1.1rem;
            box-shadow: 0 10px 22px rgba(15, 23, 42, 0.06);
        }
        .stButton > button {
            border-radius: 12px;
            font-weight: 600;
            background: linear-gradient(180deg, #2563eb, #1d4ed8);
            color: white;
            border: none;
            padding: 0.6rem 1rem;
        }
        .stButton > button:hover {
            background: linear-gradient(180deg, #1d4ed8, #1e40af);
        }
        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0f172a, #111827);
        }
        section[data-testid="stSidebar"] * {
            color: white;
        }
        [data-testid="stSidebarNavLink"] {
            border-radius: 10px;
        }
        [data-testid="stSidebarNavLink"]:hover {
            background: rgba(255,255,255,0.08);
        }
    </style>
    """,
    unsafe_allow_html=True,
)

if not st.session_state.logged_in:
    st.markdown(
        """
        <div class="hero">
          <h1>🛡️ SpamShield</h1>
          <p>Secure SMS & Email Spam Detection portal</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    login_tab, signup_tab = st.tabs(["Sign in", "Create account"])

    with login_tab:
        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Sign in", use_container_width=True)

        if submit:
            users = load_users()
            stored_hash = users.get(username)
            if verify_password(password, stored_hash):
                if stored_hash is not None and not stored_hash.startswith("pbkdf2_sha256$"):
                    save_user(username, password)
                st.session_state.logged_in = True
                st.session_state.user = username
                st.session_state.history = load_saved_history(username)
                st.rerun()
            else:
                st.error("Invalid username or password.")

        st.info("Demo accounts: admin / admin123, user / user123")

    with signup_tab:
        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        with st.form("signup_form"):
            new_username = st.text_input("Choose a username")
            new_password = st.text_input("Choose a password", type="password")
            confirm_password = st.text_input("Confirm password", type="password")
            signup = st.form_submit_button("Create account", use_container_width=True)

        if signup:
            if not new_username.strip():
                st.warning("Username cannot be empty.")
            elif len(new_password) < 4:
                st.warning("Password must be at least 4 characters long.")
            elif new_password != confirm_password:
                st.warning("Passwords do not match.")
            else:
                users = load_users()
                if new_username in users:
                    st.error("This username already exists. Please sign in instead.")
                else:
                    save_user(new_username, new_password)
                    st.session_state.logged_in = True
                    st.session_state.user = new_username
                    st.session_state.history = []
                    st.success(f"Account created successfully for {new_username}.")
                    st.rerun()

    st.stop()

st.markdown(
    """
    <div class="hero">
      <h1>🛡️ SpamShield</h1>
      <p>SMS & Email Spam Detection powered by Machine Learning</p>
    </div>
    """,
    unsafe_allow_html=True,
)

model, vectorizer, model_info = get_model()

with st.sidebar:
    st.write(f"Signed in as: {st.session_state.user.title()}")
    if st.button("Sign out"):
        st.session_state.logged_in = False
        st.session_state.user = ""
        st.session_state.history = []
        st.rerun()

nav_options = ["Detector", "Dashboard", "Insights", "About"]
if st.session_state.user == "admin":
    nav_options.insert(2, "Admin")
nav = st.sidebar.radio("Navigation", nav_options)

with st.sidebar:
    st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
    st.markdown("### Quick security tips")
    tips = [
        "Be careful with urgent financial requests.",
        "Verify links instead of clicking unknown URLs.",
        "Never share OTPs or passwords by message.",
        "Check sender details before replying.",
    ]
    for tip in tips:
        st.markdown(f"- {tip}")
    st.markdown("</div>", unsafe_allow_html=True)

if nav == "Detector":
    col1, col2, col3 = st.columns(3)
    col1.metric("Detection modes", "2", "SMS + Email")
    col2.metric("ML algorithm", "Naive Bayes")
    col3.metric("Text features", "TF-IDF")

    st.write("")
    left, right = st.columns([1.4, 1], gap="large")

    with left:
        st.subheader("Analyze a message")
        message_type = st.radio("Message type", ["SMS", "Email"], horizontal=True)
        subject = ""
        if message_type == "Email":
            subject = st.text_input("Email subject", placeholder="e.g. Account verification required")

        message = st.text_area(
            "Message text",
            height=200,
            placeholder="Paste the SMS or email body here...",
            help="Use a message you want to check. The text is processed locally by this demo.",
        )

        uploaded_file = st.file_uploader("Upload a .txt or .csv file", type=["txt", "csv"])
        if uploaded_file is not None:
            st.caption(f"Loaded file: {uploaded_file.name}")

        check = st.button("🔎 Detect spam", type="primary", use_container_width=True)

        if check:
            if uploaded_file is not None:
                texts = parse_uploaded_messages(uploaded_file)
                if not texts:
                    st.warning("The uploaded file did not contain usable text content.")
                else:
                    results = predict_messages(texts, model, vectorizer)
                    for item, result in zip(texts, results):
                        label = result["label"]
                        confidence = result["confidence"]
                        add_to_history({"text": item[:120], "label": label, "confidence": confidence})
                        render_prediction_card(item, label, confidence)
                        st.write(f"**Message:** {item}")
            else:
                combined = f"Subject: {subject}\n{message}".strip()
                if not message.strip() and not subject.strip():
                    st.warning("Please enter a message or email subject first.")
                else:
                    label, confidence = predict_message(combined, model, vectorizer)
                    add_to_history({"text": combined[:120], "label": label, "confidence": confidence})
                    render_prediction_card(combined, label, confidence)
                    if label == "spam":
                        st.write("**Advice:** Avoid clicking links or sharing passwords, OTPs, or payment details.")
                    else:
                        st.write("**Reminder:** A low spam score does not guarantee that a message is safe.")

    with right:
        st.subheader("Try a sample")
        st.caption("Click a sample to fill the message box.")
        sample_choices = {
            "🚨 Suspicious prize message": "Congratulations! You have won a free prize. Claim now by clicking the link.",
            "✉️ Ordinary personal message": "Hi, are we still meeting at the library at 4 pm today?",
            "📦 Account alert": "Your account has been suspended. Verify your login by following the secure link.",
        }

        for label, sample in sample_choices.items():
            if st.button(label, use_container_width=True):
                st.session_state["sample_note"] = sample

        if st.session_state.get("sample_note"):
            st.info(st.session_state["sample_note"])
            st.caption("Use this sample text or paste your own message to analyze it.")

        st.divider()
        st.subheader("How it works")
        st.markdown(
            """
            1. **Preprocessing** cleans and prepares text.  
            2. **TF-IDF** converts words into numeric features.  
            3. **Naive Bayes** estimates the message category.  
            4. The app shows a prediction and confidence score.
            """
        )
        st.warning("Educational prototype: predictions can be wrong. Do not use it as the sole security check.")

elif nav == "Dashboard":
    st.subheader("Detection dashboard")
    history = st.session_state.history
    if not history:
        st.info("No messages have been checked yet. Use the Detector tab to run a prediction.")
    else:
        df = pd.DataFrame(history)
        spam_count = int((df["label"] == "spam").sum())
        ham_count = int((df["label"] == "ham").sum())
        avg_confidence = float(df["confidence"].mean()) if not df.empty else 0.0

        col1, col2, col3 = st.columns(3)
        col1.metric("Checked messages", len(df))
        col2.metric("Spam detected", spam_count)
        col3.metric("Average confidence", f"{avg_confidence:.1%}")

        recent = df[["text", "label", "confidence"]].copy()
        recent["confidence"] = recent["confidence"].map(lambda value: f"{value:.1%}")
        st.dataframe(recent, use_container_width=True)

        counts = pd.DataFrame({
            "Category": ["Spam", "Safe"],
            "Count": [spam_count, ham_count],
        })
        fig = px.bar(
            counts,
            x="Category",
            y="Count",
            color="Category",
            color_discrete_map={"Spam": "#ef4444", "Safe": "#22c55e"},
            title="Recent detection breakdown",
            template="plotly_white",
        )
        fig.update_layout(
            margin=dict(l=20, r=20, t=40, b=20),
            showlegend=False,
            transition_duration=800,
        )
        st.plotly_chart(fig, use_container_width=True)

elif nav == "Insights":
    st.subheader("Threat insights")
    history = st.session_state.history
    if not history:
        st.info("No detection history yet. Run a quick check to generate security insights.")
    else:
        signal_counts = {}
        for entry in history:
            for signal in get_message_signals(entry.get("text", "")):
                signal_counts[signal] = signal_counts.get(signal, 0) + 1

        if signal_counts:
            signal_df = pd.DataFrame({"Signal": list(signal_counts.keys()), "Occurrences": list(signal_counts.values())})
            signal_df = signal_df.sort_values("Occurrences", ascending=False)
            st.dataframe(signal_df, use_container_width=True)

            insight_fig = px.bar(
                signal_df,
                x="Signal",
                y="Occurrences",
                color="Occurrences",
                color_continuous_scale="Aggrnyl",
                title="Spam signal frequency",
                template="plotly_white",
            )
            insight_fig.update_layout(
                margin=dict(l=20, r=20, t=40, b=80),
                xaxis_tickangle=-25,
                transition_duration=900,
            )
            st.plotly_chart(insight_fig, use_container_width=True)
        else:
            st.info("No repeated scam patterns were observed in your recent activity.")

elif nav == "Admin":
    st.subheader("Admin panel")
    if st.session_state.user != "admin":
        st.warning("Only the admin account can access this panel.")
    else:
        all_history = load_saved_history()
        if not all_history:
            st.info("No user activity has been recorded yet.")
        else:
            admin_df = pd.DataFrame(all_history)
            admin_df = admin_df[["timestamp", "user", "text", "label", "confidence"]].copy()
            admin_df["confidence"] = admin_df["confidence"].map(lambda value: f"{value:.1%}")
            st.dataframe(admin_df, use_container_width=True)

else:
    st.subheader("About this project")
    st.write(
        """
        This project demonstrates text classification for spam detection. The included training data is a small
        illustrative dataset so the project can run immediately. For meaningful evaluation, replace it with a
        larger, properly labeled and legally obtained SMS/email dataset, then retrain the model.
        """
    )
    st.write(f"Model data source: {model_info}")
    st.info("The app runs locally and does not send any data to external services.")

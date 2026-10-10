# SpamShield — SMS & Email Spam Detection

A beginner-friendly B.Tech project demonstrating spam classification using Python, Streamlit, TF-IDF, and Multinomial Naive Bayes.

## Features
- SMS and email text input
- Email subject support
- Spam / not-spam prediction
- Model confidence display
- Local model training from CSV
- Simple, responsive Streamlit interface

## Run locally

1. Install Python 3.10 or newer.
2. Extract this ZIP and open a terminal in the project folder.
3. Create and activate a virtual environment (optional but recommended).

   **Windows**
   ```bash
   py -m venv .venv
   .venv\Scripts\activate
   ```

   **macOS/Linux**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Start the app:
   ```bash
   streamlit run app.py
   ```
6. Open the local URL printed in the terminal (usually http://localhost:8501).

## Deploy to the web

This project is ready for simple cloud deployment via Streamlit or Docker-based hosts.

### Option 1: Streamlit Community Cloud
1. Push the repository to GitHub.
2. Open Streamlit Community Cloud.
3. Import the repository.
4. Select the app entry file: `app.py`.
5. Keep the default Python version or use 3.11.

### Option 2: Render / Railway / other PaaS
Use the included files:
- `Procfile`
- `render.yaml`
- `Dockerfile`

Example command for a generic host:
```bash
streamlit run app.py --server.address 0.0.0.0 --server.port $PORT --server.headless true
```

### Option 3: Docker
```bash
docker build -t spamshield .
docker run -p 8501:8501 spamshield
```

## Dataset format

`data/messages.csv` contains two columns:
- `text`: message body or email text
- `label`: `spam` or `ham` (`ham` means not spam)

The included data is intentionally small and illustrative, to make the project runnable immediately. It is **not** suitable for claiming real-world accuracy. For a college evaluation, obtain a larger licensed/public dataset, document its source, use a train/test split, and report precision, recall, F1-score, and confusion matrix.

## Project structure

```text
sms_email_spam_detection/
├── app.py
├── backend.py
├── requirements.txt
├── README.md
└── data/
    └── messages.csv
```

## Important limitation
The displayed confidence is the model's probability estimate, not a guarantee that a message is safe. This prototype does not connect to an inbox, send messages, or open links.

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/")
async def root():
    return HTMLResponse("""
    <html>
      <head>
        <title>SpamShield</title>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body style="font-family: Arial, sans-serif; background:#f3f7ff; padding:40px; color:#111827;">
        <div style="max-width:760px; margin:0 auto; background:white; border-radius:18px; padding:32px; box-shadow:0 10px 25px rgba(15,23,42,0.08);">
          <h1>🛡️ SpamShield</h1>
          <p>This project is now adapted for Vercel-compatible hosting.</p>
          <p>For a full working Streamlit app, use <strong>Streamlit Cloud</strong> or <strong>Render</strong>, because Streamlit itself is not a native Vercel app runtime.</p>
          <p><em>Deploy target: Vercel-compatible fallback API page</em></p>
        </div>
      </body>
    </html>
    """)

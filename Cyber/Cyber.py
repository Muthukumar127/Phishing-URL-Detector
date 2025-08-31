from flask import Flask, render_template, request
import re

app = Flask(__name__)

# Suspicious keywords
PHISHING_KEYWORDS = ["login", "verify", "secure", "update", "account", "bank", "free", "bonus", "click"]

def check_url(url: str):
    url = url.strip().lower()

    if len(url) > 100:
        return "⚠️ Suspicious (URL too long)"
    if "@" in url:
        return "⚠️ Suspicious (contains @ symbol)"
    if re.match(r"(\d{1,3}\.){3}\d{1,3}", url):
        return "⚠️ Suspicious (uses IP instead of domain)"
    for word in PHISHING_KEYWORDS:
        if word in url:
            return f"⚠️ Suspicious (contains keyword '{word}')"
    if url.count(".") > 3:
        return "⚠️ Suspicious (too many dots/subdomains)"
    return "✅ Safe URL"

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        result = check_url(url)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)

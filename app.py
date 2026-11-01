from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
import sqlite3
import re
import json
import socket
import ssl
import hashlib
import io
import os
import uuid
from PIL import Image, ImageChops, ImageEnhance, UnidentifiedImageError
from werkzeug.utils import secure_filename
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "deeptrace.db"
UPLOAD_DIR = APP_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_IMAGE_BYTES = 8 * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

app = Flask(__name__)
app.secret_key = os.environ.get("DEEPTRACE_SECRET", "deeptrace-local-student-project-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_IMAGE_BYTES

# ---------------- DATABASE ----------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                summary TEXT NOT NULL,
                findings TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.commit()

def save_investigation(kind, target, score, level, summary, findings):
    created = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO investigations
               (kind, target, risk_score, risk_level, summary, findings, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (kind, target, score, level, summary, json.dumps(findings), created)
        )
        conn.commit()
        return cur.lastrowid

def get_level(score):
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"

def clamp_score(score):
    return max(0, min(100, int(score)))

# ---------------- ANALYSIS HELPERS ----------------

SUSPICIOUS_WORDS = [
    "urgent", "verify now", "account suspended", "password", "otp",
    "one time password", "bank details", "click here", "claim reward",
    "won a prize", "limited time", "act now", "payment failed",
    " KYC", "kyc update", "refund pending", "blocked"
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}
RISKY_TLDS = {".zip", ".mov", ".top", ".click", ".work", ".country", ".gq", ".tk"}

def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Please enter a website link.")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("That does not look like a valid website link.")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https website links are supported.")
    return raw, parsed

def analyze_url(raw, do_live=True):
    url, parsed = normalize_url(raw)
    host = (parsed.hostname or "").lower().strip(".")
    findings = []
    score = 0

    def add(points, title, detail, status="warning"):
        nonlocal score
        score += points
        findings.append({"title": title, "detail": detail, "status": status})

    if parsed.scheme == "http":
        add(15, "Connection is not encrypted", "This link uses HTTP instead of HTTPS. Information sent to it may not be protected.")
    else:
        findings.append({"title": "Encrypted connection requested", "detail": "The link uses HTTPS. This is helpful, but it does not prove the website is trustworthy.", "status": "good"})

    if "@" in parsed.netloc:
        add(25, "Unusual @ symbol in link", "The @ symbol can make a link display one address while sending visitors somewhere else.")

    if len(url) > 100:
        add(10, "Very long link", "Long links can hide the real destination. Check the domain carefully.")

    if host.startswith("xn--") or ".xn--" in host:
        add(20, "Unusual domain characters", "This domain uses special encoded characters. Some fake websites use look-alike letters.")

    if host.count("-") >= 3:
        add(10, "Many hyphens in the domain", "A domain with several hyphens deserves an extra careful look.")

    if re.search(r"\d{4,}", host):
        add(10, "Many numbers in the domain", "A long string of numbers in a domain can be a warning sign.")

    if host in SHORTENERS:
        add(15, "Shortened link", "The real destination is hidden behind a link-shortening service.")

    if any(host.endswith(tld) for tld in RISKY_TLDS):
        add(10, "Less common domain ending", "This domain ending is less common. That alone does not mean it is harmful.")

    if host.count(".") >= 4:
        add(10, "Many subdomains", "The address has several sections before the main domain. Check that the main domain is correct.")

    known_brand_words = ["paypal", "google", "amazon", "microsoft", "apple", "netflix", "instagram", "facebook", "sbi", "hdfc", "icici"]
    for brand in known_brand_words:
        if brand in host and not (host == brand + ".com" or host.endswith("." + brand + ".com") or host == brand + ".in" or host.endswith("." + brand + ".in")):
            add(20, "Possible brand name imitation", f"The domain contains the word '{brand}' but is not an obvious official {brand} domain. Check the address independently.")
            break

    if not findings:
        findings.append({"title": "No obvious warning signs found", "detail": "This quick check did not find common suspicious patterns. It is not a guarantee that the website is safe.", "status": "good"})

    live_info = {"checked": False, "reachable": None, "status_code": None, "final_url": None, "note": "Live check was not performed."}
    if do_live:
        live_info = check_live_url(url)
        if live_info.get("reachable") is False:
            findings.append({"title": "Website did not respond", "detail": live_info.get("note", "The website could not be reached during this check."), "status": "warning"})
            score += 5
        elif live_info.get("reachable") is True:
            findings.append({"title": "Website responded", "detail": f"The website replied with HTTP status {live_info.get('status_code')}. A response does not mean it is trustworthy.", "status": "good"})

    score = clamp_score(score)
    level = get_level(score)
    summary = {
        "High": "Several warning signs were found. Avoid entering passwords, OTPs or payment details until you verify the website independently.",
        "Medium": "Some warning signs were found. Check the website address carefully before sharing information.",
        "Low": "Few common warning signs were found. Still use caution and verify important websites independently."
    }[level]
    return {
        "kind": "Link",
        "target": url,
        "risk_score": score,
        "risk_level": level,
        "summary": summary,
        "findings": findings,
        "domain": host,
        "live_info": live_info
    }

def check_live_url(url):
    result = {"checked": True, "reachable": None, "status_code": None, "final_url": None, "note": ""}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DeepTraceStudentProject/1.0"}, method="HEAD")
        with urllib.request.urlopen(req, timeout=5, context=ssl.create_default_context()) as response:
            result.update({"reachable": True, "status_code": response.status, "final_url": response.geturl(), "note": "Website responded to a basic HEAD request."})
    except urllib.error.HTTPError as e:
        result.update({"reachable": True, "status_code": e.code, "final_url": url, "note": f"Website replied with status {e.code}."})
    except Exception as e:
        result.update({"reachable": False, "note": "The website could not be reached. It may be offline, block automated checks or have a connection issue."})
    return result

def analyze_message(message):
    text = (message or "").strip()
    if not text:
        raise ValueError("Please paste a message to check.")
    lower = text.lower()
    findings = []
    score = 0
    matches = [word.strip() for word in SUSPICIOUS_WORDS if word.strip().lower() in lower]
    if matches:
        score += min(45, len(matches) * 12)
        findings.append({
            "title": "Pressure or account-warning language",
            "detail": "We found words or phrases often used in scam messages: " + ", ".join(matches[:8]) + ". Real organisations usually do not pressure you to share secret codes.",
            "status": "warning"
        })
    urls = re.findall(r"(?:https?://|www\.)[^\s<>]+", text, flags=re.I)
    if urls:
        score += min(30, len(urls) * 15)
        findings.append({"title": "Link included in the message", "detail": f"The message contains {len(urls)} link(s). Do not open an unexpected link until you verify who sent it.", "status": "warning"})
    if re.search(r"\b(otp|one[- ]time password|cvv|pin|password)\b", lower):
        score += 25
        findings.append({"title": "Secret information requested or mentioned", "detail": "Never share an OTP, PIN, CVV or password with someone who contacts you unexpectedly.", "status": "warning"})
    if re.search(r"\b(won|winner|prize|lottery|free gift)\b", lower):
        score += 15
        findings.append({"title": "Prize or reward claim", "detail": "Unexpected prize messages can be used to get money or personal information.", "status": "warning"})
    if re.search(r"\b(pay|payment|transfer|fee|deposit|refund)\b", lower):
        score += 10
        findings.append({"title": "Money-related wording", "detail": "The message mentions money or a payment. Confirm requests through the organisation's official app or phone number.", "status": "warning"})
    if not findings:
        findings.append({"title": "No common scam phrases found", "detail": "This message did not match the simple warning patterns used by DeepTrace. That does not prove it is genuine.", "status": "good"})
    score = clamp_score(score)
    level = get_level(score)
    summary = {
        "High": "This message contains several common scam warning signs. Do not share codes, passwords or money. Contact the organisation through its official channel.",
        "Medium": "This message has some warning signs. Verify the sender and any request independently before taking action.",
        "Low": "Few common warning signs were found. Be careful with unexpected requests, even when a message looks normal."
    }[level]
    return {"kind": "Message", "target": text[:180] + ("..." if len(text) > 180 else ""), "risk_score": score,
            "risk_level": level, "summary": summary, "findings": findings, "links_found": urls}

def investigate_domain(domain_input):
    raw = (domain_input or "").strip()
    if not raw:
        raise ValueError("Enter a domain name, such as example.com.")
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.split("/")[0].split(":")[0].lower().strip(".")
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", raw):
        raise ValueError("Enter a domain in a format like example.com.")
    findings = []
    ips = []
    try:
        ips = sorted(set(item[4][0] for item in socket.getaddrinfo(raw, None)))
        findings.append({"title": "Domain address found", "detail": "The domain currently points to: " + ", ".join(ips[:5]), "status": "good"})
    except Exception:
        findings.append({"title": "No address found", "detail": "A DNS address could not be found. The domain may not exist or may be temporarily unavailable.", "status": "warning"})
    score = 0
    if raw.startswith("xn--") or ".xn--" in raw:
        score += 20
        findings.append({"title": "Special encoded domain name", "detail": "This domain uses encoded characters. Check carefully for look-alike names.", "status": "warning"})
    if raw.count("-") >= 3:
        score += 10
        findings.append({"title": "Several hyphens", "detail": "Several hyphens can make a domain harder to read. This is only a clue, not proof of a scam.", "status": "warning"})
    if not score:
        findings.append({"title": "No basic domain pattern warning", "detail": "No simple pattern warning was found. This does not confirm that the domain is legitimate.", "status": "good"})
    level = get_level(score)
    summary = "This is a basic domain lookup, not a full security certification. Verify the domain owner and official website before trusting it."
    return {"kind": "Domain", "target": raw, "risk_score": score, "risk_level": level, "summary": summary,
            "findings": findings, "ip_addresses": ips}

# ---------------- ROUTES ----------------

@app.route("/")
def dashboard():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM investigations WHERE risk_level='High'").fetchone()[0]
        recent = conn.execute("SELECT * FROM investigations ORDER BY id DESC LIMIT 5").fetchall()
        counts = conn.execute("SELECT kind, COUNT(*) AS total FROM investigations GROUP BY kind").fetchall()
    return render_template("dashboard.html", total=total, high=high, recent=recent, counts=counts)

@app.route("/link-checker", methods=["GET", "POST"])
def link_checker():
    result = None
    if request.method == "POST":
        try:
            result = analyze_url(request.form.get("url"), do_live=True)
            result["id"] = save_investigation(result["kind"], result["target"], result["risk_score"], result["risk_level"], result["summary"], result["findings"])
        except ValueError as e:
            flash(str(e), "error")
    return render_template("link_checker.html", result=result)

@app.route("/message-checker", methods=["GET", "POST"])
def message_checker():
    result = None
    if request.method == "POST":
        try:
            result = analyze_message(request.form.get("message"))
            result["id"] = save_investigation(result["kind"], result["target"], result["risk_score"], result["risk_level"], result["summary"], result["findings"])
        except ValueError as e:
            flash(str(e), "error")
    return render_template("message_checker.html", result=result)

@app.route("/domain-investigator", methods=["GET", "POST"])
def domain_investigator():
    result = None
    if request.method == "POST":
        try:
            result = investigate_domain(request.form.get("domain"))
            result["id"] = save_investigation(result["kind"], result["target"], result["risk_score"], result["risk_level"], result["summary"], result["findings"])
        except ValueError as e:
            flash(str(e), "error")
    return render_template("domain_investigator.html", result=result)

@app.route("/reports")
def reports():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM investigations ORDER BY id DESC").fetchall()
    return render_template("reports.html", rows=rows)

@app.route("/report/<int:report_id>")
def report_detail(report_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id=?", (report_id,)).fetchone()
    if not row:
        flash("That report could not be found.", "error")
        return redirect(url_for("reports"))
    report = dict(row)
    report["findings"] = json.loads(report["findings"])
    return render_template("report_detail.html", report=report)

@app.route("/history")
def history():
    q = request.args.get("q", "").strip()
    kind = request.args.get("kind", "All")
    query = "SELECT * FROM investigations WHERE 1=1"
    params = []
    if q:
        query += " AND target LIKE ?"
        params.append(f"%{q}%")
    if kind in ("Link", "Message", "Domain", "Photo"):
        query += " AND kind=?"
        params.append(kind)
    query += " ORDER BY id DESC"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return render_template("history.html", rows=rows, q=q, kind=kind)

@app.route("/delete-report/<int:report_id>", methods=["POST"])
def delete_report(report_id):
    with get_db() as conn:
        conn.execute("DELETE FROM investigations WHERE id=?", (report_id,))
        conn.commit()
    flash("Report deleted.", "success")
    return redirect(request.referrer or url_for("history"))

@app.route("/export/<int:report_id>")
def export_report(report_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id=?", (report_id,)).fetchone()
    if not row:
        flash("Report not found.", "error")
        return redirect(url_for("reports"))
    report = dict(row)
    findings = json.loads(report["findings"])
    lines = [
        "DEEPTRACE INVESTIGATION REPORT",
        "=" * 34,
        f"Report ID: {report['id']}",
        f"Type: {report['kind']}",
        f"Checked item: {report['target']}",
        f"Risk score: {report['risk_score']}/100",
        f"Risk level: {report['risk_level']}",
        f"Date: {report['created_at']}",
        "",
        "SUMMARY",
        report["summary"],
        "",
        "FINDINGS"
    ]
    for item in findings:
        lines += [f"- {item['title']}: {item['detail']}"]
    lines += ["", "Note: DeepTrace provides basic indicators, not a guarantee or professional security certification."]
    return Response("\n".join(lines), mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename=deeptrace-report-{report_id}.txt"})

# ---------------- IMAGE / PHOTO CHECKER ----------------

def analyse_photo(file_storage):
    """Inspect file facts and editing clues. This is forensic triage, not an AI detector verdict."""
    if not file_storage or not file_storage.filename:
        raise ValueError("Choose a photo first.")
    original_name = secure_filename(file_storage.filename) or "uploaded-image"
    suffix = Path(original_name).suffix.lower()
    if suffix not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("Use a JPG, JPEG, PNG or WEBP image.")
    raw = file_storage.read(MAX_IMAGE_BYTES + 1)
    if not raw:
        raise ValueError("The selected file is empty.")
    if len(raw) > MAX_IMAGE_BYTES:
        raise ValueError("Image is too large. Please use an image under 8 MB.")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        image = Image.open(io.BytesIO(raw))
        image.verify()
        image = Image.open(io.BytesIO(raw))
        image.load()
    except (UnidentifiedImageError, OSError, ValueError):
        raise ValueError("This file is not a readable image. Try another JPG, PNG or WEBP.")

    width, height = image.size
    fmt = (image.format or suffix.lstrip(".")).upper()
    exif = image.getexif()
    exif_names = {"Make": 271, "Model": 272, "DateTime": 306, "Software": 305, "Artist": 315}
    metadata = {}
    for label, tag in exif_names.items():
        value = exif.get(tag)
        if value:
            metadata[label] = str(value)[:160]
    software = metadata.get("Software", "")
    findings = []
    score = 0

    if metadata.get("Make") or metadata.get("Model"):
        findings.append({"title": "Camera details are present", "detail": "The file contains camera make or model information. This can support an origin check, but metadata can be changed.", "status": "good"})
    else:
        findings.append({"title": "No camera details found", "detail": "No camera make/model was found. Many social apps remove metadata, and AI images may also lack it. This alone is not proof of AI generation.", "status": "warning"})
        score += 8
    if software:
        findings.append({"title": "Editing software is named", "detail": f"The metadata lists: {software}. This may indicate editing or exporting, but normal photo apps also write software details.", "status": "warning"})
        score += 12
    else:
        findings.append({"title": "No editing software name found", "detail": "No software tag was found. This does not prove the image is original.", "status": "good"})

    if fmt in {"JPEG", "JPG"}:
        # Error Level Analysis: recompress at a fixed quality and measure differences.
        rgb = image.convert("RGB")
        buffer = io.BytesIO()
        rgb.save(buffer, format="JPEG", quality=90)
        buffer.seek(0)
        recompressed = Image.open(buffer).convert("RGB")
        diff = ImageChops.difference(rgb, recompressed)
        enhanced = ImageEnhance.Brightness(diff).enhance(4)
        ela_name = f"ela-{uuid.uuid4().hex}.jpg"
        enhanced.thumbnail((1200, 1200))
        enhanced.save(UPLOAD_DIR / ela_name, format="JPEG", quality=88)
        import statistics
        channels = diff.getdata()
        # Sample at most ~50k pixels to keep the app responsive.
        step = max(1, len(channels) // 50000)
        sample = list(channels)[::step]
        mean_diff = sum((r + g + b) / 3 for r, g, b in sample) / max(1, len(sample))
        if mean_diff > 12:
            findings.append({"title": "JPEG compression differences are noticeable", "detail": "The recompression comparison found visible pixel differences. This can happen after editing, resizing, repeated saving or normal image processing. It is not proof of manipulation.", "status": "warning"})
            score += 12
        else:
            findings.append({"title": "No strong JPEG compression difference", "detail": "This simple comparison found no unusually strong overall difference. Small edits can still go unnoticed.", "status": "good"})
        ela_url = ela_name
    else:
        findings.append({"title": "Compression comparison not available", "detail": "The ELA comparison is currently used for JPEG files. PNG and WEBP files are checked using file facts and metadata only.", "status": "info"})
        ela_url = None

    if width < 256 or height < 256:
        findings.append({"title": "Small image dimensions", "detail": "The image is quite small, so fine details may not be reliable for visual review.", "status": "info"})
    else:
        findings.append({"title": "Image dimensions recorded", "detail": f"The image is {width} × {height} pixels.", "status": "good"})

    # The app intentionally does not pretend that metadata or ELA can prove AI generation.
    findings.append({"title": "AI-generated image check", "detail": "No trained AI-image classification model is connected in this offline version. File clues cannot reliably tell whether a picture was made by AI. Treat this result as a basic authenticity review, not an AI verdict.", "status": "info"})
    level = get_level(clamp_score(score))
    summary = {
        "High": "Several file clues deserve a closer look. They do not prove the photo is fake or AI-generated.",
        "Medium": "Some file clues were found. Check the source and compare with an original copy if possible.",
        "Low": "Few basic warning clues were found. This does not prove the photo is genuine or camera-original."
    }[level]
    # Save the original only after successful validation; use an unguessable filename.
    stored_name = f"{uuid.uuid4().hex}{suffix}"
    (UPLOAD_DIR / stored_name).write_bytes(raw)
    return {
        "kind": "Photo", "target": original_name, "risk_score": clamp_score(score), "risk_level": level,
        "summary": summary, "findings": findings,
        "photo": {"filename": original_name, "stored_name": stored_name, "format": fmt,
                  "width": width, "height": height, "bytes": len(raw), "sha256": digest,
                  "metadata": metadata, "ela_image": ela_url}
    }

@app.route("/photo-checker", methods=["GET", "POST"])
def photo_checker():
    result = None
    if request.method == "POST":
        try:
            result = analyse_photo(request.files.get("photo"))
            result["id"] = save_investigation(result["kind"], result["target"], result["risk_score"], result["risk_level"], result["summary"], result["findings"])
        except ValueError as e:
            flash(str(e), "error")
    return render_template("photo_checker.html", result=result)

@app.route("/photo-file/<path:filename>")
def photo_file(filename):
    # Only serve generated image-analysis previews, never arbitrary paths.
    if not re.fullmatch(r"ela-[a-f0-9]{32}\.jpg", filename):
        return "Not found", 404
    from flask import send_from_directory
    return send_from_directory(UPLOAD_DIR, filename, mimetype="image/jpeg", as_attachment=False)

@app.route("/guide")
def guide():
    return render_template("guide.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.errorhandler(413)
def too_large(error):
    flash("That upload is too large. Please choose a file under 8 MB.", "error")
    return redirect(url_for("photo_checker")), 413

@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404

init_db()

if __name__ == "__main__":
    # Accessible from other devices on the same Wi-Fi network.
    app.run(host="0.0.0.0", port=5000, debug=False)

from functools import cache
import json
from flask import (
    Flask,
    make_response,
    redirect,
    request,
    jsonify,
    render_template,
    send_from_directory,
    send_file,
    session,
    url_for,
)
import os
import json
import requests
from datetime import datetime
import dotenv
import markdown
import markdown.extensions.fenced_code
from flask_session import Session
from yubico_client import Yubico
from functools import wraps
import hmac
import hashlib

dotenv.load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(24))
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
Session(app)

# Yubikey settings
YUBICO_CLIENT_ID = os.getenv("YUBICO_CLIENT_ID")
YUBICO_SECRET_KEY = os.getenv("YUBICO_SECRET_KEY")
YUBIKEY_ID = os.getenv("YUBIKEY_ID")  # The first 12 characters of your YubiKey OTP

# Authentication function
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def find(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)

# Assets routes
@app.route("/assets/<path:path>")
def send_assets(path):
    if path.endswith(".json"):
        return send_from_directory(
            "templates/assets", path, mimetype="application/json"
        )

    if os.path.isfile("templates/assets/" + path):
        return send_from_directory("templates/assets", path)

    # Try looking in one of the directories
    filename: str = path.split("/")[-1]
    if (
        filename.endswith(".png")
        or filename.endswith(".jpg")
        or filename.endswith(".jpeg")
        or filename.endswith(".svg")
    ):
        if os.path.isfile("templates/assets/img/" + filename):
            return send_from_directory("templates/assets/img", filename)
        if os.path.isfile("templates/assets/img/favicon/" + filename):
            return send_from_directory("templates/assets/img/favicon", filename)

    return render_template("404.html"), 404


# region Special routes
@app.route("/favicon.png")
def faviconPNG():
    return send_from_directory("templates/assets/img", "favicon.png")


@app.route("/.well-known/<path:path>")
def wellknown(path):
    # Try to proxy to https://nathan.woodburn.au/.well-known/
    req = requests.get(f"https://nathan.woodburn.au/.well-known/{path}")
    return make_response(
        req.content, 200, {"Content-Type": req.headers["Content-Type"]}
    )


# endregion


# region Main routes
@app.route("/")
def index():
    return render_template("index.html", authenticated=session.get('authenticated', False))

# Login and authentication routes
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        otp = request.form.get("otp", "")
        
        # Verify the first 12 characters of the OTP match the expected YubiKey ID
        if not otp or len(otp) < 12 or otp[:12] != YUBIKEY_ID:
            error = "Invalid YubiKey OTP"
        else:
            try:
                # Initialize Yubico client
                client = Yubico(YUBICO_CLIENT_ID, YUBICO_SECRET_KEY)
                
                # Verify the OTP with Yubico servers
                verification = client.verify(otp)
                if verification:
                    session['authenticated'] = True
                    next_url = request.args.get('next', url_for('emergency'))
                    return redirect(next_url)
                else:
                    error = "YubiKey authentication failed"
            except Exception as e:
                error = f"Authentication error: {str(e)}"
    
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('index'))

@app.route("/emergency")
@login_required
def emergency():
    # Check if emergency.md exists
    emergency_path = os.path.join(os.path.dirname(__file__), "emergency.md")
    
    if os.path.exists(emergency_path):
        with open(emergency_path, 'r') as f:
            emergency_content = f.read()
            # Convert markdown to HTML with enhanced extensions
            emergency_html = markdown.markdown(
                emergency_content,
                extensions=[
                    'fenced_code',
                    'codehilite',
                    'tables',
                    'nl2br',
                    'sane_lists'  # Ensures proper list rendering
                ]
            )
            return render_template("emergency.html", content=emergency_html)
    else:
        return render_template("emergency.html", 
                              content="<p>No emergency information available.</p>")

@app.route("/<path:path>")
def catch_all(path: str):
    if os.path.isfile("templates/" + path):
        return render_template(path)

    # Try with .html
    if os.path.isfile("templates/" + path + ".html"):
        return render_template(path + ".html")

    if os.path.isfile("templates/" + path.strip("/") + ".html"):
        return render_template(path.strip("/") + ".html")

    # Try to find a file matching
    if path.count("/") < 1:
        # Try to find a file matching
        filename = find(path, "templates")
        if filename:
            return send_file(filename)

    return render_template("404.html"), 404


# endregion


# region Webhook
@app.route("/webhook/update", methods=["POST"])
def webhook_update():
    # Get the webhook secret from environment
    webhook_secret = os.getenv("WEBHOOK_SECRET")
    if not webhook_secret:
        return jsonify({"error": "Webhook not configured"}), 500
    
    # Verify X-Webhook-Signature header
    signature = request.headers.get("X-Webhook-Signature")
    if not signature:
        return jsonify({"error": "Missing signature"}), 401
    
    # Get request body
    payload = request.get_data()
    
    # Verify signature
    expected_signature = hmac.new(
        webhook_secret.encode(), 
        payload, 
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({"error": "Invalid signature"}), 401
    
    # Process the update
    try:
        data = request.json
        if not data or not isinstance(data, dict) or "content" not in data:
            return jsonify({"error": "Invalid payload format"}), 400
        
        emergency_content = data["content"]
        emergency_path = os.path.join(os.path.dirname(__file__), "emergency.md")
        
        # Write the new content to the file
        with open(emergency_path, "w") as f:
            f.write(emergency_content)
        
        return jsonify({"success": True, "message": "Emergency content updated"}), 200
    
    except Exception as e:
        app.logger.error(f"Webhook error: {str(e)}")
        return jsonify({"error": f"Update failed: {str(e)}"}), 500

# endregion


# region Error Catching
# 404 catch all
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# endregion
if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")

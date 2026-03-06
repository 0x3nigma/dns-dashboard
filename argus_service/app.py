from flask import Flask, jsonify
import subprocess
import json
# APP
app = Flask(__name__)

def run_argus(domain, extra_flags=[]):
    command = ["python", "argus.py", domain] + extra_flags + ["--json"]

    result = subprocess.run(
        command,
        capture_output=True,   # capture stdout and stderr instead of printing
        text=True,             # return output as string, not bytes
        cwd="/app/argus"       # run the command from the argus directory
    )

    if result.returncode != 0:
        raise Exception(result.stderr or "Argus scan failed")

    # parse the JSON string output into a Python dict and return it
    return json.loads(result.stdout)


# ─── ROUTE 1: Health Check ─────────────────────────────────────────────────
# Standard DevOps health check — Docker will ping this to verify
# the container is alive and ready to serve requests
#
# GET /health
# Response: { "status": "ok" }

@app.route("/health")
def health():
    return jsonify({ "status": "ok" })


# ─── ROUTE 2: Full Scan ────────────────────────────────────────────────────
# Runs a full Argus scan on the domain
# Returns all DNS records, DNSSEC status, zone transfer attempt etc.
#
# GET /scan/<domain>
# Example: GET /scan/google.com
# Response: { ...full argus output as JSON... }

@app.route("/scan/<domain>")
def scan(domain):
    try:
        data = run_argus(domain)
        return jsonify(data)
    except Exception as e:
        # return 500 with the error message if something goes wrong
        return jsonify({ "error": str(e) }), 500


# ─── ROUTE 3: DNSSEC Only ──────────────────────────────────────────────────
# Runs Argus with the --dnssec flag only
# Faster than a full scan — just checks DNSSEC status
#
# GET /dnssec/<domain>
# Example: GET /dnssec/cloudflare.com
# Response: { ...dnssec output... }

@app.route("/dnssec/<domain>")
def dnssec(domain):
    try:
        # pass --dnssec as an extra flag to Argus
        data = run_argus(domain, ["--dnssec", "--nameserver", "8.8.8.8"])
        return jsonify(data)
    except Exception as e:
        return jsonify({ "error": str(e) }), 500


# ─── ROUTE 4: Compare flag Only ──────────────────────────────────────────────────
@app.route("/compare/<domain>")
def compare(domain):
    try:
        data = run_argus(domain, ["--compare"])
        return jsonify(data)
    except Exception as e:
        return jsonify({ "error": str(e) }), 500

# ─── START SERVER ──────────────────────────────────────────────────────────
# host="0.0.0.0" → listen on all network interfaces inside the container
# Without this, Flask only listens on localhost INSIDE the container
# and other containers (like Node.js) won't be able to reach it
#
# port=5000 → Flask's default port

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

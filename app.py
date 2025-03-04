from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

# Load scan results
def load_results():
    results_file = "xss_scan_results.json"
    if os.path.exists(results_file):
        with open(results_file, "r") as f:
            return json.load(f)
    return []

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/results")
def api_results():
    return jsonify(load_results())

if __name__ == "__main__":
    app.run(debug=True)
import sys
import os

# Ensure project dir is on path for _sm4 import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify
from crypto_engine import process, get_algorithms

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/algorithms")
def algorithms():
    return jsonify(get_algorithms())


@app.route("/api/process", methods=["POST"])
def api_process():
    data = request.get_json()
    if not data:
        return jsonify({"error": "请提供 JSON 数据"}), 400

    algorithm = data.get("algorithm", "")
    action = data.get("action", "")
    input_text = data.get("input", "")
    key = data.get("key", "")

    if not algorithm or not action:
        return jsonify({"error": "缺少 algorithm 或 action 参数"}), 400
    if not input_text:
        return jsonify({"error": "请输入内容"}), 400

    result = process(algorithm, action, input_text, key)
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

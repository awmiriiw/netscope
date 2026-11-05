import os
import threading

from typing import Any
from werkzeug.wrappers import Response
from flask import Flask, render_template, jsonify, current_app

from config.settings import setting
from utils.netscope_logger import RecordLog

logger = RecordLog(__name__)
web_dir = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(web_dir, "templates"),
    static_folder=os.path.join(web_dir, "static"),
)


def get_graph() -> Any | None:
    """ """

    return current_app.config.get("graph")


def get_sniffer() -> Any | None:
    """ """

    return current_app.config.get("sniffer")


@app.route("/")
def index() -> str:
    """ """

    return render_template("index.html")


@app.route("/data")
def data() -> Response:
    """ """

    graph = get_graph()

    if not graph:

        return jsonify({"nodes": [], "edges": []})

    try:
        result = graph.get_graph_data()

        logger.info(f"[API] nodes={len(result['nodes'])} edges={len(result['edges'])}")

        return jsonify(result)

    except Exception as e:
        logger.error(f"[DATA ERROR] {e}", exc_info=True)

        return jsonify({"nodes": [], "edges": []})


@app.route("/status")
def status() -> Response:
    """ """

    sniffer = get_sniffer()

    try:
        return jsonify({"is_running": sniffer.is_running() if sniffer else False})

    except Exception:
        return jsonify({"is_running": False})


@app.route("/start_capture", methods=["POST"])
def start_capture() -> Response:
    """ """

    sniffer = get_sniffer()

    if sniffer:
        threading.Thread(target=sniffer.start, daemon=True).start()

    return jsonify({"status": "started"})


@app.route("/stop_capture", methods=["POST"])
def stop_capture() -> Response:
    """ """

    sniffer = get_sniffer()

    if sniffer:
        sniffer.stop()

    return jsonify({"status": "stopped"})


@app.route("/clear_data", methods=["POST"])
def clear_data() -> Response:
    """ """

    graph = get_graph()

    if graph:
        graph.clear()

    return jsonify({"status": "cleared"})


@app.route("/node_info/<node_id>")
def node_info(node_id: str) -> Response:
    """ """

    graph = get_graph()

    if not graph:

        return jsonify({"error": "no graph"})

    try:

        return jsonify({"id": node_id, "exists": node_id in graph.graph.nodes})

    except Exception:

        return jsonify({"error": "failed"})


def run_server(graph: Any, sniffer: Any) -> None:
    """ """

    app.config["graph"] = graph
    app.config["sniffer"] = sniffer

    logger.info(
        f"Server running at http://{setting.WEB_SERVER_HOST}:{setting.WEB_SERVER_PORT}"
    )

    app.run(
        host=setting.WEB_SERVER_HOST,
        port=setting.WEB_SERVER_PORT,
        debug=False,
        threaded=True,
    )

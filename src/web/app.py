import os
from config import settings
from utils.logger import logger
from flask import Flask, render_template, jsonify

web_dir = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(web_dir, 'templates'), static_folder=os.path.join(web_dir, 'templates'))
network_graph_instance = None
sniffer_instance = None


@app.route('/')
def index():
    """Serves the main dashboard page."""
    
    return render_template('index.html', update_interval=settings.GRAPH_UPDATE_INTERVAL)

@app.route('/data')
def data():
    """Returns graph data."""
    
    if network_graph_instance:
        graph_data = network_graph_instance.get_graph_data()
        return jsonify(graph_data)
    return jsonify({'nodes': [], 'edges': []})

@app.route('/node_info/<node_id>')
def node_info(node_id):
    """Provides detailed information for a specific node."""
    
    if network_graph_instance:
        info = network_graph_instance.get_node_info(node_id)
        if info:
            return jsonify(info)
    return jsonify({"error": "Node not found"}), 404

@app.route('/start_capture', methods=['POST'])
def start_capture():
    """Starts packet capturing via the sniffer."""
    
    if sniffer_instance:
        sniffer_instance.start()
        return jsonify({"status": "success", "message": "Capture started."})
    return jsonify({"status": "error", "message": "Sniffer not initialized."}), 500

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    """Stops packet capturing via the sniffer."""
    
    if sniffer_instance:
        sniffer_instance.stop()
        return jsonify({"status": "success", "message": "Capture stopped."})
    return jsonify({"status": "error", "message": "Sniffer not initialized."}), 500

@app.route('/clear_data', methods=['POST'])
def clear_data():
    """Clears all captured graph data."""
    
    if network_graph_instance:
        network_graph_instance.clear()
        return jsonify({"status": "success", "message": "Graph data cleared."})
    return jsonify({"status": "error", "message": "Graph not initialized."}), 500

@app.route('/status')
def status():
    """Returns the current status of the sniffer."""
    
    running = sniffer_instance.is_running() if sniffer_instance else False
    return jsonify({"is_running": running})

def run_server(graph, sniffer):
    """Runs the web server with access to graph and sniffer objects."""
    
    global network_graph_instance, sniffer_instance
    network_graph_instance = graph
    sniffer_instance = sniffer
    logger.info(f"Starting web server on http://{settings.WEB_SERVER_HOST}:{settings.WEB_SERVER_PORT}")
    try:
        app.run(host=settings.WEB_SERVER_HOST, port=settings.WEB_SERVER_PORT, debug=False)
    except OSError as e:
        logger.error(f"Failed to start web server: {e}")
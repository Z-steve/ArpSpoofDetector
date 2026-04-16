# Import necessary modules from Flask for creating a web server and handling JSON responses
from flask import Flask, jsonify, send_from_directory
from .controller.detector import ARPSpooferDetector
import os

# Initialize the Flask application
app = Flask(__name__, static_folder="../static")
# Create an instance of ARPSpooferDetector to handle ARP spoofing detection logic
detector = ARPSpooferDetector()


# Define a route for the different roots URL to serve the main frontend page and functions
@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/arp-events')
def serve_events():
    return send_from_directory(app.static_folder, 'arp-events.html')

@app.route('/about')
def serve_about():
    return send_from_directory(app.static_folder, 'about.html')

@app.route('/api/devices', methods=['GET'])
def get_devices():
    devices = [d.to_dict() for d in detector.cache.get_devices()]
    return jsonify(devices)

@app.route('/api/events', methods=['GET'])
def get_events():
    events = [e.to_dict() for e in detector.cache.get_events()]
    return jsonify(events)

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    detector.start_sniffing()
    return jsonify({'status': 'started'})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    detector.stop_sniffing()
    return jsonify({'status': 'stopped'})

@app.route('/api/status')  # New endpoint
def get_monitoring_status():
    return jsonify({'monitoring': detector.running})

@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({
        'interface': detector.iface,
        'subnet': detector.cache.subnet,
        'gateway_ip': detector.cache.gateway_ip,
        'detector_ip': detector.cache.detector_ip,
        'detector_mac': detector.cache.detector_mac,
        'capture_available': detector.cache.capture_available
    })


if __name__ == "__main__":
    # Ensure the static folder exists and create it if it does not exists
    if not os.path.exists('../static'):
        os.makedirs('../static')
    # Run the Flask application on all network interfaces and on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
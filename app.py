#!/usr/bin/env python3
"""
CTI Platform - Main Flask Application
Comprehensive Cyber Threat Intelligence Platform
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import sys
import json
import threading
from datetime import datetime

# Import our custom modules
from modules.url_scanner import URLScanner
from modules.file_scanner import FileScanner
from modules.usb_monitor import USBMonitor
from modules.report_generator import ReportGenerator
from modules.threat_database import ThreatDatabase

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cti_platform_secret_key_2024'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORTS_FOLDER'] = 'reports'

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize modules
url_scanner = URLScanner()
file_scanner = FileScanner()
usb_monitor = USBMonitor()
report_generator = ReportGenerator()
threat_db = ThreatDatabase()

# Create necessary directories
os.makedirs('uploads', exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)
os.makedirs('templates', exist_ok=True)

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/dashboard/stats')
def dashboard_stats():
    """Get dashboard statistics"""
    stats = {
        'total_scans': threat_db.get_total_scans(),
        'threats_detected': threat_db.get_threats_count(),
        'clean_files': threat_db.get_clean_files_count(),
        'open_ports': threat_db.get_open_ports_count(),
        'recent_threats': threat_db.get_recent_threats(5),
        'system_status': {
            'realtime_protection': True,
            'firewall': True,
            'usb_monitoring': usb_monitor.is_monitoring(),
            'database_updated': True
        }
    }
    return jsonify(stats)

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    """Scan URL for threats and vulnerabilities"""
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    def scan_task():
        # Emit progress updates via WebSocket
        socketio.emit('scan_progress', {'progress': 10, 'status': 'Starting URL scan...'})
        
        # Perform URL scanning
        result = url_scanner.scan_url(url)
        
        socketio.emit('scan_progress', {'progress': 50, 'status': 'Scanning for threats...'})
        
        # Port scanning
        ports = url_scanner.scan_ports(url)
        result['open_ports'] = ports
        
        socketio.emit('scan_progress', {'progress': 80, 'status': 'Analyzing results...'})
        
        # Store results in database
        scan_id = threat_db.store_url_scan(url, result)
        result['scan_id'] = scan_id
        
        socketio.emit('scan_progress', {'progress': 100, 'status': 'Scan completed'})
        socketio.emit('scan_complete', result)
        
        return result
    
    # Start scanning in background thread
    thread = threading.Thread(target=scan_task)
    thread.start()
    
    return jsonify({'status': 'Scan started', 'message': 'URL scan initiated'})

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """Scan uploaded file for malware"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Save uploaded file
    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    def scan_task():
        socketio.emit('scan_progress', {'progress': 10, 'status': 'Analyzing file...'})
        
        # Perform file scanning
        result = file_scanner.scan_file(filepath)
        result['filename'] = filename
        
        socketio.emit('scan_progress', {'progress': 70, 'status': 'Checking threat database...'})
        
        # Store results
        scan_id = threat_db.store_file_scan(filename, result)
        result['scan_id'] = scan_id
        
        socketio.emit('scan_progress', {'progress': 100, 'status': 'File scan completed'})
        socketio.emit('file_scan_complete', result)
        
        # Clean up uploaded file
        try:
            os.remove(filepath)
        except:
            pass
    
    thread = threading.Thread(target=scan_task)
    thread.start()
    
    return jsonify({'status': 'File scan started', 'filename': filename})

@app.route('/api/usb/monitor')
def usb_monitor_status():
    """Get USB monitoring status"""
    status = {
        'monitoring': usb_monitor.is_monitoring(),
        'connected_devices': usb_monitor.get_connected_devices(),
        'recent_activity': usb_monitor.get_recent_activity()
    }
    return jsonify(status)

@app.route('/api/usb/start-monitor', methods=['POST'])
def start_usb_monitor():
    """Start USB monitoring"""
    def monitor_callback(event_data):
        socketio.emit('usb_event', event_data)
    
    success = usb_monitor.start_monitoring(monitor_callback)
    return jsonify({'success': success, 'monitoring': usb_monitor.is_monitoring()})

@app.route('/api/usb/stop-monitor', methods=['POST'])
def stop_usb_monitor():
    """Stop USB monitoring"""
    usb_monitor.stop_monitoring()
    return jsonify({'success': True, 'monitoring': False})

@app.route('/api/usb/scan/<device_id>')
def scan_usb_device(device_id):
    """Scan specific USB device"""
    def scan_task():
        socketio.emit('scan_progress', {'progress': 20, 'status': 'Scanning USB device...'})
        
        result = usb_monitor.scan_device(device_id)
        
        socketio.emit('scan_progress', {'progress': 80, 'status': 'Analyzing threats...'})
        
        scan_id = threat_db.store_usb_scan(device_id, result)
        result['scan_id'] = scan_id
        
        socketio.emit('scan_progress', {'progress': 100, 'status': 'USB scan completed'})
        socketio.emit('usb_scan_complete', result)
    
    thread = threading.Thread(target=scan_task)
    thread.start()
    
    return jsonify({'status': 'USB scan started', 'device_id': device_id})

@app.route('/api/reports')
def get_reports():
    """Get list of available reports"""
    reports = threat_db.get_all_reports()
    return jsonify(reports)

@app.route('/api/report/generate/<scan_type>/<scan_id>')
def generate_report(scan_type, scan_id):
    """Generate and download report"""
    scan_data = threat_db.get_scan_data(scan_type, scan_id)
    
    if not scan_data:
        return jsonify({'error': 'Scan data not found'}), 404
    
    # Generate PDF report
    report_path = report_generator.generate_pdf_report(scan_type, scan_data)
    
    return send_file(report_path, as_attachment=True, 
                    download_name=f'{scan_type}_report_{scan_id}.pdf')

@app.route('/api/report/download/<format>/<scan_type>/<scan_id>')
def download_report(format, scan_type, scan_id):
    """Download report in specified format"""
    scan_data = threat_db.get_scan_data(scan_type, scan_id)
    
    if not scan_data:
        return jsonify({'error': 'Scan data not found'}), 404
    
    if format == 'pdf':
        report_path = report_generator.generate_pdf_report(scan_type, scan_data)
        return send_file(report_path, as_attachment=True)
    elif format == 'json':
        report_path = report_generator.generate_json_report(scan_type, scan_data)
        return send_file(report_path, as_attachment=True)
    elif format == 'csv':
        report_path = report_generator.generate_csv_report(scan_type, scan_data)
        return send_file(report_path, as_attachment=True)
    else:
        return jsonify({'error': 'Invalid format'}), 400

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'status': 'Connected to CTI Platform'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    print("Starting CTI Platform...")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

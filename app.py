"""
CyberWatch - Network Security Dashboard
Main Flask Application
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
from scanner import NetworkScanner
import json
import os
from datetime import datetime

app = Flask(__name__)
scanner = NetworkScanner()

# Store scan history
scan_history = []

@app.route('/')
def index():
    """Dashboard home page"""
    stats = scanner.get_stats()
    return render_template('index.html', 
                         devices=scanner.devices, 
                         stats=stats,
                         scan_time=scanner.scan_time)

@app.route('/scan')
def scan_network():
    """Trigger a new network scan"""
    network, _ = scanner.get_network_range()
    devices = scanner.scan_network(network)
    
    # Save to history
    if devices:
        scan_history.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'devices': len(devices),
            'devices_list': devices
        })
    
    return redirect(url_for('index'))

@app.route('/device/<ip>')
def device_detail(ip):
    """Show details for a specific device"""
    device = None
    for d in scanner.devices:
        if d['ip'] == ip:
            device = d
            break
    
    if device:
        # Scan ports for this device
        device['ports'] = scanner.scan_ports(ip)
        return render_template('device_detail.html', device=device)
    
    return redirect(url_for('index'))

@app.route('/api/devices')
def api_devices():
    """API endpoint for device data"""
    return jsonify(scanner.devices)

@app.route('/api/scan')
def api_scan():
    """API endpoint to trigger scan"""
    network, _ = scanner.get_network_range()
    devices = scanner.scan_network(network)
    return jsonify({'status': 'success', 'devices': len(devices)})

@app.route('/reports')
def reports():
    """View scan history"""
    return render_template('reports.html', history=scan_history)

@app.route('/export/<format>')
def export_report(format):
    """Export scan results"""
    if format == 'json':
        return jsonify(scanner.devices)
    elif format == 'txt':
        # Create text report
        report = f"Network Scan Report\n"
        report += f"Generated: {datetime.now()}\n"
        report += f"{'='*50}\n\n"
        for device in scanner.devices:
            report += f"IP: {device['ip']}\n"
            report += f"MAC: {device['mac']}\n"
            report += f"Vendor: {device['vendor']}\n"
            report += f"Status: {device['status']}\n"
            report += "-"*30 + "\n"
        return report, 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    # Create necessary folders
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000)
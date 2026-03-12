"""
DataVault UI Tabs Module
Defines all tab interfaces and layouts
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                              QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                              QTextEdit, QProgressBar, QComboBox, QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QIcon
import json
from core.collectors import IPInfoCollector, BreachCollector, WebScraper, VulnerabilityScanner, VPSMonitor
from core.export import Exporter


class CollectorThread(QThread):
    """Background thread for data collection"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, collector_func, target):
        super().__init__()
        self.collector_func = collector_func
        self.target = target
    
    def run(self):
        try:
            result = self.collector_func(self.target)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class IPLookupTab(QWidget):
    """IP/Domain Lookup Tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.collector_thread = None
        self.current_result = None
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("IP/Domain Lookup")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Input section
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address or domain (e.g., 8.8.8.8 or google.com)")
        input_layout.addWidget(self.target_input)
        
        self.lookup_btn = QPushButton("🔍 Lookup")
        self.lookup_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #388bfd;
            }
            QPushButton:pressed {
                background-color: #1158c7;
            }
        """)
        self.lookup_btn.clicked.connect(self.perform_lookup)
        input_layout.addWidget(self.lookup_btn)
        layout.addLayout(input_layout)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results display
        layout.addWidget(QLabel("Results:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            background-color: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 6px;
            color: #c9d1d9;
            font-family: 'Courier New', monospace;
        """)
        layout.addWidget(self.results_text)
        
        # Info label
        info_label = QLabel("✓ No API key required - Uses DNS resolution")
        info_label.setStyleSheet("color: #58a6ff; font-size: 10pt; font-style: italic; padding: 5px 0;")
        layout.addWidget(info_label)
        
        # Export button
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.export_json_btn = QPushButton("📥 JSON")
        self.export_json_btn.setEnabled(False)
        self.export_json_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1f6feb;
            }
            QPushButton:disabled {
                background-color: #30363d;
                color: #6e7681;
            }
        """)
        self.export_json_btn.clicked.connect(lambda: self.export_result("json"))
        export_layout.addWidget(self.export_json_btn)
        
        self.export_csv_btn = QPushButton("📥 CSV")
        self.export_csv_btn.setEnabled(False)
        self.export_csv_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1f6feb;
            }
            QPushButton:disabled {
                background-color: #30363d;
                color: #6e7681;
            }
        """)
        self.export_csv_btn.clicked.connect(lambda: self.export_result("csv"))
        export_layout.addWidget(self.export_csv_btn)
        layout.addLayout(export_layout)
        
        self.setLayout(layout)
    
    def perform_lookup(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter an IP or domain")
            return
        
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.lookup_btn.setEnabled(False)
        
        self.collector_thread = CollectorThread(IPInfoCollector.collect, target)
        self.collector_thread.finished.connect(self.on_lookup_complete)
        self.collector_thread.error.connect(self.on_error)
        self.collector_thread.start()
    
    def on_lookup_complete(self, result):
        self.current_result = result
        self.progress.setValue(100)
        self.progress.setVisible(False)
        self.lookup_btn.setEnabled(True)
        
        # Display results with formatted GeoIP data
        display_text = f"Target: {result['target']}\n"
        display_text += f"Timestamp: {result['timestamp']}\n"
        display_text += f"Status: {result.get('data', {}).get('status', 'unknown')}\n\n"
        
        if result.get('error'):
            display_text += f"Error: {result['error']}"
        else:
            data = result.get('data', {})
            
            # Basic info
            display_text += "═" * 70 + "\n"
            display_text += "BASIC INFORMATION\n"
            display_text += "═" * 70 + "\n"
            if 'resolved_ip' in data:
                display_text += f"IP Address:        {data['resolved_ip']}\n"
            if 'reverse_dns' in data:
                display_text += f"Reverse DNS:       {data['reverse_dns']}\n"
            
            # GeoIP data
            if 'geoip' in data and data['geoip']:
                geoip = data['geoip']
                display_text += "\n" + "═" * 70 + "\n"
                display_text += "GEOLOCATION\n"
                display_text += "═" * 70 + "\n"
                
                if geoip.get('city'):
                    display_text += f"City:              {geoip.get('city', 'N/A')}\n"
                if geoip.get('region'):
                    display_text += f"Region:            {geoip.get('region', 'N/A')}\n"
                if geoip.get('country_name'):
                    display_text += f"Country:           {geoip.get('country_name', 'N/A')} ({geoip.get('country_code', 'N/A')})\n"
                if geoip.get('timezone_name'):
                    display_text += f"Timezone:          {geoip.get('timezone_name', 'N/A')} (UTC{geoip.get('utc_offset', '+0')})\n"
                if geoip.get('latitude'):
                    display_text += f"Latitude:          {geoip.get('latitude', 'N/A')}\n"
                if geoip.get('longitude'):
                    display_text += f"Longitude:         {geoip.get('longitude', 'N/A')}\n"
                if geoip.get('postal_code'):
                    display_text += f"Postal Code:       {geoip.get('postal_code', 'N/A')}\n"
                
                display_text += "\n" + "═" * 70 + "\n"
                display_text += "ISP & ORGANIZATION\n"
                display_text += "═" * 70 + "\n"
                
                if geoip.get('isp'):
                    display_text += f"ISP:               {geoip.get('isp', 'N/A')}\n"
                if geoip.get('org'):
                    display_text += f"Organization:      {geoip.get('org', 'N/A')}\n"
                if geoip.get('asn'):
                    display_text += f"ASN:               {geoip.get('asn', 'N/A')}\n"
                if geoip.get('hostname'):
                    display_text += f"Hostname:          {geoip.get('hostname', 'N/A')}\n"
                
                display_text += "\n" + "═" * 70 + "\n"
                display_text += "CONNECTION TYPE\n"
                display_text += "═" * 70 + "\n"
                
                if geoip.get('connection_type'):
                    display_text += f"Type:              {geoip.get('connection_type', 'N/A')}\n"
                if geoip.get('is_vpn') is not None:
                    display_text += f"VPN:               {'Yes' if geoip.get('is_vpn') else 'No'}\n"
                if geoip.get('is_proxy') is not None:
                    display_text += f"Proxy:             {'Yes' if geoip.get('is_proxy') else 'No'}\n"
                if geoip.get('is_hosting') is not None:
                    display_text += f"Hosting:           {'Yes' if geoip.get('is_hosting') else 'No'}\n"
                if geoip.get('is_torrent') is not None:
                    display_text += f"Torrent:           {'Yes' if geoip.get('is_tor') else 'No'}\n"
                if geoip.get('threat_level'):
                    display_text += f"Threat Level:      {geoip.get('threat_level', 'N/A').title()}\n"
                
                display_text += "\n" + "═" * 70 + "\n"
                display_text += "ADDITIONAL INFO\n"
                display_text += "═" * 70 + "\n"
                
                if geoip.get('currency_code'):
                    display_text += f"Currency:          {geoip.get('currency_code', 'N/A')} ({geoip.get('currency_name', 'N/A')})\n"
                if geoip.get('language_code'):
                    display_text += f"Language:          {geoip.get('language_code', 'N/A')} ({geoip.get('language_name', 'N/A')})\n"
                if geoip.get('accuracy_radius'):
                    display_text += f"Accuracy Radius:   {geoip.get('accuracy_radius', 'N/A')} km\n"
        
        self.results_text.setText(display_text)
        self.export_json_btn.setEnabled(True)
        self.export_csv_btn.setEnabled(True)
    
    def on_error(self, error):
        self.progress.setVisible(False)
        self.lookup_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Lookup failed: {error}")
    
    def export_result(self, format_type):
        if not self.current_result:
            return
        
        try:
            if format_type == "json":
                path = Exporter.export_json([self.current_result])
                QMessageBox.information(self, "Success", f"Exported to:\n{path}")
            elif format_type == "csv":
                path = Exporter.export_csv([self.current_result])
                QMessageBox.information(self, "Success", f"Exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {e}")


class BreachCheckTab(QWidget):
    """Breach Check Tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.collector_thread = None
        self.current_result = None
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Breach Checker")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Input section
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Email/Domain:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter email address or domain")
        input_layout.addWidget(self.target_input)
        
        self.check_btn = QPushButton("⚠️ Check")
        self.check_btn.setStyleSheet("""
            QPushButton {
                background-color: #da3633;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #f85149;
            }
            QPushButton:pressed {
                background-color: #da3633;
            }
        """)
        self.check_btn.clicked.connect(self.perform_check)
        input_layout.addWidget(self.check_btn)
        layout.addLayout(input_layout)
        
        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Results
        layout.addWidget(QLabel("Results:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            background-color: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 6px;
            color: #c9d1d9;
            font-family: 'Courier New', monospace;
        """)
        layout.addWidget(self.results_text)
        
        # Export
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.export_btn = QPushButton("📥 Export JSON")
        self.export_btn.setEnabled(False)
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1f6feb;
            }
            QPushButton:disabled {
                background-color: #30363d;
                color: #6e7681;
            }
        """)
        self.export_btn.clicked.connect(self.export_result)
        export_layout.addWidget(self.export_btn)
        layout.addLayout(export_layout)
        
        self.setLayout(layout)
    
    def perform_check(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter an email or domain")
            return
        
        self.progress.setVisible(True)
        self.check_btn.setEnabled(False)
        
        self.collector_thread = CollectorThread(BreachCollector.collect, target)
        self.collector_thread.finished.connect(self.on_check_complete)
        self.collector_thread.error.connect(self.on_error)
        self.collector_thread.start()
    
    def on_check_complete(self, result):
        self.current_result = result
        self.progress.setVisible(False)
        self.check_btn.setEnabled(True)
        
        display_text = f"Target: {result['target']}\n"
        display_text += f"Timestamp: {result['timestamp']}\n\n"
        
        if result.get('error'):
            display_text += f"Error: {result['error']}"
        else:
            data = result.get('data', {})
            if data.get('breached'):
                display_text += f"⚠️ BREACHED - Found in {data.get('breach_count', 0)} breaches\n\n"
                display_text += "Breaches:\n"
                for breach in data.get('breaches', []):
                    display_text += f"  • {breach.get('name')} ({breach.get('date')})\n"
            else:
                display_text += "✓ Not found in any known breaches"
        
        self.results_text.setText(display_text)
        self.export_btn.setEnabled(True)
    
    def on_error(self, error):
        self.progress.setVisible(False)
        self.check_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Check failed: {error}")
    
    def export_result(self):
        if not self.current_result:
            return
        path = Exporter.export_json([self.current_result])
        QMessageBox.information(self, "Success", f"Exported to:\n{path}")


class WebScraperTab(QWidget):
    """Web Scraper Tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.collector_thread = None
        self.current_result = None
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("Web Scraper")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL")
        input_layout.addWidget(self.url_input)
        
        self.scrape_btn = QPushButton("🕷️ Scrape")
        self.scrape_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1f6feb;
            }
        """)
        self.scrape_btn.clicked.connect(self.perform_scrape)
        input_layout.addWidget(self.scrape_btn)
        layout.addLayout(input_layout)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        layout.addWidget(QLabel("Content:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            background-color: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 6px;
            color: #c9d1d9;
            font-family: 'Courier New', monospace;
        """)
        layout.addWidget(self.results_text)
        
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.export_btn = QPushButton("📥 Export JSON")
        self.export_btn.setEnabled(False)
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1f6feb;
            }
            QPushButton:disabled {
                background-color: #30363d;
                color: #6e7681;
            }
        """)
        self.export_btn.clicked.connect(self.export_result)
        export_layout.addWidget(self.export_btn)
        layout.addLayout(export_layout)
        
        self.setLayout(layout)
    
    def perform_scrape(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a URL")
            return
        
        self.progress.setVisible(True)
        self.scrape_btn.setEnabled(False)
        
        self.collector_thread = CollectorThread(WebScraper.collect, url)
        self.collector_thread.finished.connect(self.on_scrape_complete)
        self.collector_thread.error.connect(self.on_error)
        self.collector_thread.start()
    
    def on_scrape_complete(self, result):
        self.current_result = result
        self.progress.setVisible(False)
        self.scrape_btn.setEnabled(True)
        
        display_text = f"URL: {result['target']}\n"
        display_text += f"Timestamp: {result['timestamp']}\n\n"
        
        if result.get('error'):
            display_text += f"Error: {result['error']}"
        else:
            data = result.get('data', {})
            display_text += "Page Information:\n"
            for key, value in data.items():
                if key != 'text_preview':
                    display_text += f"  {key}: {value}\n"
            display_text += f"\nText Preview (first 500 chars):\n{data.get('text_preview', 'N/A')}"
        
        self.results_text.setText(display_text)
        self.export_btn.setEnabled(True)
    
    def on_error(self, error):
        self.progress.setVisible(False)
        self.scrape_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Scrape failed: {error}")
    
    def export_result(self):
        if not self.current_result:
            return
        path = Exporter.export_json([self.current_result])
        QMessageBox.information(self, "Success", f"Exported to:\n{path}")


class VulnScanTab(QWidget):
    """Vulnerability Scanner Tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.collector_thread = None
        self.current_result = None
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("Vulnerability Scanner")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter URL or IP address")
        input_layout.addWidget(self.target_input)
        
        self.scan_btn = QPushButton("🛡️ Scan")
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #d29922;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #e3b341;
            }
            QPushButton:pressed {
                background-color: #bf8700;
            }
        """)
        self.scan_btn.clicked.connect(self.perform_scan)
        input_layout.addWidget(self.scan_btn)
        layout.addLayout(input_layout)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        layout.addWidget(QLabel("Results:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            background-color: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 6px;
            color: #c9d1d9;
            font-family: 'Courier New', monospace;
        """)
        layout.addWidget(self.results_text)
        
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.export_btn = QPushButton("📥 Export JSON")
        self.export_btn.setEnabled(False)
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1f6feb;
            }
            QPushButton:disabled {
                background-color: #30363d;
                color: #6e7681;
            }
        """)
        self.export_btn.clicked.connect(self.export_result)
        export_layout.addWidget(self.export_btn)
        layout.addLayout(export_layout)
        
        self.setLayout(layout)
    
    def perform_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return
        
        self.progress.setVisible(True)
        self.scan_btn.setEnabled(False)
        
        self.collector_thread = CollectorThread(VulnerabilityScanner.collect, target)
        self.collector_thread.finished.connect(self.on_scan_complete)
        self.collector_thread.error.connect(self.on_error)
        self.collector_thread.start()
    
    def on_scan_complete(self, result):
        self.current_result = result
        self.progress.setVisible(False)
        self.scan_btn.setEnabled(True)
        
        display_text = f"Target: {result['target']}\n"
        display_text += f"Timestamp: {result['timestamp']}\n\n"
        
        if result.get('error'):
            display_text += f"Error: {result['error']}"
        else:
            data = result.get('data', {})
            score = data.get('security_score', 0)
            display_text += f"Security Score: {score}/100\n"
            display_text += f"Status Code: {data.get('status_code', 'N/A')}\n\n"
            display_text += "Security Checks:\n"
            for check, status in data.get('checks', {}).items():
                status_icon = "✓" if status else "✗"
                display_text += f"  {status_icon} {check}: {status}\n"
        
        self.results_text.setText(display_text)
        self.export_btn.setEnabled(True)
    
    def on_error(self, error):
        self.progress.setVisible(False)
        self.scan_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Scan failed: {error}")
    
    def export_result(self):
        if not self.current_result:
            return
        path = Exporter.export_json([self.current_result])
        QMessageBox.information(self, "Success", f"Exported to:\n{path}")


class VPSMonitorTab(QWidget):
    """VPS Monitor Tab"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.collector_thread = None
        self.current_result = None
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("VPS Monitor")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Enter server IP or hostname")
        input_layout.addWidget(self.host_input)
        
        self.monitor_btn = QPushButton("📊 Check Status")
        self.monitor_btn.setStyleSheet("""
            QPushButton {
                background-color: #1f6feb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #388bfd;
            }
            QPushButton:pressed {
                background-color: #1158c7;
            }
        """)
        self.monitor_btn.clicked.connect(self.perform_monitor)
        input_layout.addWidget(self.monitor_btn)
        layout.addLayout(input_layout)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        layout.addWidget(QLabel("Status:"))
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            background-color: #0d1117; 
            border: 2px solid #30363d; 
            border-radius: 6px;
            color: #c9d1d9;
            font-family: 'Courier New', monospace;
        """)
        layout.addWidget(self.results_text)
        
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.export_btn = QPushButton("📥 Export JSON")
        self.export_btn.setEnabled(False)
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1f6feb;
            }
            QPushButton:disabled {
                background-color: #30363d;
                color: #6e7681;
            }
        """)
        self.export_btn.clicked.connect(self.export_result)
        export_layout.addWidget(self.export_btn)
        layout.addLayout(export_layout)
        
        self.setLayout(layout)
    
    def perform_monitor(self):
        host = self.host_input.text().strip()
        if not host:
            QMessageBox.warning(self, "Error", "Please enter a host")
            return
        
        self.progress.setVisible(True)
        self.monitor_btn.setEnabled(False)
        
        self.collector_thread = CollectorThread(VPSMonitor.collect, host)
        self.collector_thread.finished.connect(self.on_monitor_complete)
        self.collector_thread.error.connect(self.on_error)
        self.collector_thread.start()
    
    def on_monitor_complete(self, result):
        self.current_result = result
        self.progress.setVisible(False)
        self.monitor_btn.setEnabled(True)
        
        display_text = f"Host: {result['target']}\n"
        display_text += f"Timestamp: {result['timestamp']}\n\n"
        
        if result.get('error'):
            display_text += f"Error: {result['error']}"
        else:
            data = result.get('data', {})
            if data.get('online'):
                display_text += "✓ Server is ONLINE\n\n"
                display_text += f"Status Code: {data.get('status_code')}\n"
                display_text += f"Response Time: {data.get('response_time'):.2f}s"
            else:
                display_text += "✗ Server is OFFLINE\n\n"
                display_text += f"Error: {data.get('error_type', 'Unknown')}"
        
        self.results_text.setText(display_text)
        self.export_btn.setEnabled(True)
    
    def on_error(self, error):
        self.progress.setVisible(False)
        self.monitor_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", f"Monitor failed: {error}")
    
    def export_result(self):
        if not self.current_result:
            return
        path = Exporter.export_json([self.current_result])
        QMessageBox.information(self, "Success", f"Exported to:\n{path}")

"""
DataVault Main Window
Contains the main application window and tab management
"""

from PyQt6.QtWidgets import QMainWindow, QTabWidget, QVBoxLayout, QWidget, QMenu, QStatusBar, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon, QColor
from ui.tabs import (IPLookupTab, BreachCheckTab, WebScraperTab, 
                     VulnScanTab, VPSMonitorTab)


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        # Window properties
        self.setWindowTitle("DataVault - Multi-Source Intelligence Collector")
        self.setGeometry(100, 100, 1400, 900)
        
        # Set application stylesheet for modern dark theme
        self.setStyleSheet(self.get_stylesheet())
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Title bar - Modern dark gradient appearance
        title_widget = QWidget()
        title_widget.setStyleSheet("background-color: #0d1117; border-bottom: 2px solid #30363d;")
        title_layout = QVBoxLayout()
        title_label = QLabel("🔐 DataVault - Intelligence Collector")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #58a6ff; padding: 15px 20px; font-weight: bold;")
        title_layout.addWidget(title_label)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_widget.setLayout(title_layout)
        title_widget.setFixedHeight(70)
        layout.addWidget(title_widget)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background-color: #161b22;
            }
            QTabBar {
                background-color: #0d1117;
                border-bottom: 2px solid #30363d;
            }
            QTabBar::tab {
                background-color: #21262d;
                color: #8b949e;
                padding: 12px 24px;
                margin-right: 4px;
                border: none;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background-color: #161b22;
                color: #58a6ff;
                border-bottom: 3px solid #1f6feb;
            }
            QTabBar::tab:hover:!selected {
                background-color: #262c36;
                color: #c9d1d9;
            }
        """)
        
        # Add tabs
        self.ip_tab = IPLookupTab()
        self.breach_tab = BreachCheckTab()
        self.scraper_tab = WebScraperTab()
        self.vuln_tab = VulnScanTab()
        self.vps_tab = VPSMonitorTab()
        
        self.tabs.addTab(self.ip_tab, "🔍 IP/Domain Lookup")
        self.tabs.addTab(self.breach_tab, "⚠️ Breach Check")
        self.tabs.addTab(self.scraper_tab, "🕷️ Web Scraper")
        self.tabs.addTab(self.vuln_tab, "🛡️ Vulnerability Scan")
        self.tabs.addTab(self.vps_tab, "📊 VPS Monitor")
        
        layout.addWidget(self.tabs)
        
        # Status bar
        status_bar = QStatusBar()
        status_bar.setStyleSheet("background-color: #0d1117; border-top: 2px solid #30363d; color: #8b949e;")
        status_label = QLabel("✓ Ready")
        status_bar.addWidget(status_label)
        self.setStatusBar(status_bar)
        
        central_widget.setLayout(layout)
    
    def get_stylesheet(self):
        """Return the application stylesheet - Modern Dark Theme"""
        return """
            QMainWindow {
                background-color: #161b22;
            }
            QWidget {
                background-color: #161b22;
                color: #c9d1d9;
            }
            QLabel {
                color: #c9d1d9;
                font-weight: 500;
            }
            QLineEdit {
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 10px 12px;
                background-color: #0d1117;
                color: #c9d1d9;
                selection-background-color: #1f6feb;
                font-size: 11pt;
            }
            QLineEdit:focus {
                border: 2px solid #58a6ff;
                background-color: #0d1117;
            }
            QTextEdit {
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                background-color: #0d1117;
                color: #c9d1d9;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
            }
            QTextEdit:focus {
                border: 2px solid #58a6ff;
                background-color: #0d1117;
            }
            QPushButton {
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 11pt;
                border: none;
                color: white;
                background-color: #1f6feb;
            }
            QPushButton:hover {
                background-color: #388bfd;
            }
            QPushButton:pressed {
                background-color: #1158c7;
            }
            QPushButton:disabled {
                opacity: 0.6;
                background-color: #21262d;
                color: #6e7681;
            }
            QProgressBar {
                border: 2px solid #30363d;
                border-radius: 6px;
                text-align: center;
                height: 28px;
                background-color: #0d1117;
                color: #58a6ff;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #1f6feb;
                border-radius: 4px;
            }
            QMessageBox {
                background-color: #161b22;
            }
            QMessageBox QLabel {
                color: #c9d1d9;
            }
            QComboBox {
                border: 2px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                background-color: #0d1117;
                color: #c9d1d9;
                font-size: 11pt;
            }
            QComboBox:focus {
                border: 2px solid #58a6ff;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
                background-color: #0d1117;
            }
            QComboBox::down-arrow {
                image: none;
                border: none;
                width: 0px;
            }
        """

"""
DataVault Export Module
Handles exporting results to CSV, JSON, and PDF
"""

import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

class Exporter:
    """Handles all export operations"""
    
    @staticmethod
    def export_json(data: List[Dict[str, Any]], filename: str = None) -> str:
        """Export data to JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"results_{timestamp}.json"
        
        file_path = Path("results") / filename
        file_path.parent.mkdir(exist_ok=True)
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        
        return str(file_path)
    
    @staticmethod
    def export_csv(data: List[Dict[str, Any]], filename: str = None) -> str:
        """Export data to CSV"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"results_{timestamp}.csv"
        
        file_path = Path("results") / filename
        file_path.parent.mkdir(exist_ok=True)
        
        if not data:
            return ""
        
        # Flatten nested dictionaries for CSV
        flattened = []
        for item in data:
            flat = {"target": item.get("target"), "timestamp": item.get("timestamp")}
            if isinstance(item.get("data"), dict):
                flat.update(item["data"])
            if item.get("error"):
                flat["error"] = item["error"]
            flattened.append(flat)
        
        with open(file_path, 'w', newline='') as f:
            if flattened:
                writer = csv.DictWriter(f, fieldnames=flattened[0].keys())
                writer.writeheader()
                writer.writerows(flattened)
        
        return str(file_path)
    
    @staticmethod
    def export_pdf(data: List[Dict[str, Any]], filename: str = None) -> str:
        """Export data to PDF"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
        except ImportError:
            return "Error: reportlab not installed"
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"results_{timestamp}.pdf"
        
        file_path = Path("results") / filename
        file_path.parent.mkdir(exist_ok=True)
        
        # Create PDF
        doc = SimpleDocTemplate(str(file_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph("<b>DataVault Results</b>", styles['Heading1'])
        story.append(title)
        story.append(Spacer(1, 0.3*inch))
        
        # Date
        date_para = Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
        story.append(date_para)
        story.append(Spacer(1, 0.2*inch))
        
        # Results table
        if data:
            table_data = [["Target", "Status", "Key Info"]]
            for item in data:
                target = item.get("target", "N/A")
                status = "Error" if item.get("error") else "Success"
                info = json.dumps(item.get("data", {}))[:100]
                table_data.append([target, status, info])
            
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
        
        try:
            doc.build(story)
            return str(file_path)
        except Exception as e:
            return f"Error creating PDF: {e}"

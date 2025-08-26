#!/usr/bin/env python3
"""
Report Generator Module
Generates reports in various formats (PDF, JSON, CSV)
"""

import os
import json
import csv
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

class ReportGenerator:
    def __init__(self):
        self.reports_dir = 'reports'
        os.makedirs(self.reports_dir, exist_ok=True)
        
    def generate_pdf_report(self, scan_type, scan_data):
        """Generate PDF report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{scan_type}_report_{timestamp}.pdf'
        filepath = os.path.join(self.reports_dir, filename)
        
        doc = SimpleDocTemplate(filepath, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=colors.darkblue,
            spaceAfter=30
        )
        
        story.append(Paragraph('CTI Platform - Security Report', title_style))
        story.append(Spacer(1, 12))
        
        # Report metadata
        metadata_data = [
            ['Report Type', scan_type.replace('_', ' ').title()],
            ['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Scan Target', self._get_scan_target(scan_type, scan_data)],
            ['Status', scan_data.get('status', 'Unknown').upper()]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 20))
        
        # Threats section
        if scan_data.get('threats'):
            story.append(Paragraph('Detected Threats', styles['Heading1']))
            story.append(Spacer(1, 12))
            
            threat_data = [['#', 'Threat Description']]
            for i, threat in enumerate(scan_data['threats'], 1):
                threat_data.append([str(i), threat])
            
            threat_table = Table(threat_data, colWidths=[0.5*inch, 5.5*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(threat_table)
            story.append(Spacer(1, 20))
        
        # Scan-specific sections
        if scan_type == 'url':
            self._add_url_report_sections(story, scan_data, styles)
        elif scan_type == 'file':
            self._add_file_report_sections(story, scan_data, styles)
        elif scan_type == 'usb':
            self._add_usb_report_sections(story, scan_data, styles)
        
        # Summary and recommendations
        story.append(Paragraph('Summary and Recommendations', styles['Heading1']))
        story.append(Spacer(1, 12))
        
        recommendations = self._get_recommendations(scan_type, scan_data)
        for rec in recommendations:
            story.append(Paragraph(f'• {rec}', styles['Normal']))
            story.append(Spacer(1, 6))
        
        # Build PDF
        doc.build(story)
        return filepath
    
    def generate_json_report(self, scan_type, scan_data):
        """Generate JSON report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{scan_type}_report_{timestamp}.json'
        filepath = os.path.join(self.reports_dir, filename)
        
        report_data = {
            'report_metadata': {
                'type': scan_type,
                'generated': datetime.now().isoformat(),
                'version': '1.0'
            },
            'scan_data': scan_data
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return filepath
    
    def generate_csv_report(self, scan_type, scan_data):
        """Generate CSV report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{scan_type}_report_{timestamp}.csv'
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Header
            writer.writerow(['CTI Platform Security Report'])
            writer.writerow([f'Report Type: {scan_type}'])
            writer.writerow([f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
            writer.writerow([])
            
            # Threats
            if scan_data.get('threats'):
                writer.writerow(['Threats Detected'])
                writer.writerow(['#', 'Description'])
                for i, threat in enumerate(scan_data['threats'], 1):
                    writer.writerow([i, threat])
                writer.writerow([])
            
            # Additional data based on scan type
            if scan_type == 'url':
                self._add_url_csv_data(writer, scan_data)
            elif scan_type == 'file':
                self._add_file_csv_data(writer, scan_data)
            elif scan_type == 'usb':
                self._add_usb_csv_data(writer, scan_data)
        
        return filepath
    
    def _get_scan_target(self, scan_type, scan_data):
        """Get scan target description"""
        if scan_type == 'url':
            return scan_data.get('url', 'Unknown URL')
        elif scan_type == 'file':
            return scan_data.get('filename', 'Unknown File')
        elif scan_type == 'usb':
            return scan_data.get('device_id', 'Unknown Device')
        else:
            return 'Unknown Target'
    
    def _add_url_report_sections(self, story, scan_data, styles):
        """Add URL-specific report sections"""
        # Open ports section
        if scan_data.get('open_ports'):
            story.append(Paragraph('Open Ports Found', styles['Heading1']))
            story.append(Spacer(1, 12))
            
            ports_data = [['Port', 'Service', 'State']]
            for port_info in scan_data['open_ports']:
                ports_data.append([
                    str(port_info.get('port', '')),
                    port_info.get('service', ''),
                    port_info.get('state', '')
                ])
            
            ports_table = Table(ports_data, colWidths=[1*inch, 2*inch, 1*inch])
            ports_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(ports_table)
            story.append(Spacer(1, 20))
        
        # Technical details
        details = scan_data.get('details', {})
        if details:
            story.append(Paragraph('Technical Details', styles['Heading1']))
            story.append(Spacer(1, 12))
            
            details_data = []
            for key, value in details.items():
                details_data.append([key.replace('_', ' ').title(), str(value)])
            
            details_table = Table(details_data, colWidths=[2*inch, 4*inch])
            details_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(details_table)
            story.append(Spacer(1, 20))
    
    def _add_file_report_sections(self, story, scan_data, styles):
        """Add file-specific report sections"""
        # File information
        file_info = scan_data.get('file_info', {})
        if file_info:
            story.append(Paragraph('File Information', styles['Heading1']))
            story.append(Spacer(1, 12))
            
            file_data = []
            for key, value in file_info.items():
                file_data.append([key.replace('_', ' ').title(), str(value)])
            
            file_table = Table(file_data, colWidths=[2*inch, 4*inch])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightgreen),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(file_table)
            story.append(Spacer(1, 20))
        
        # Hash analysis
        hash_analysis = scan_data.get('hash_analysis', {})
        if hash_analysis:
            story.append(Paragraph('Hash Analysis', styles['Heading1']))
            story.append(Spacer(1, 12))
            
            hash_data = []
            for hash_type, hash_value in hash_analysis.items():
                hash_data.append([hash_type.upper(), hash_value])
            
            hash_table = Table(hash_data, colWidths=[1*inch, 5*inch])
            hash_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(hash_table)
            story.append(Spacer(1, 20))
    
    def _add_usb_report_sections(self, story, scan_data, styles):
        """Add USB-specific report sections"""
        # Scan summary
        scan_summary = scan_data.get('scan_summary', {})
        if scan_summary:
            story.append(Paragraph('Scan Summary', styles['Heading1']))
            story.append(Spacer(1, 12))
            
            summary_data = []
            for key, value in scan_summary.items():
                summary_data.append([key.replace('_', ' ').title(), str(value)])
            
            summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightyellow),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(summary_table)
            story.append(Spacer(1, 20))
        
        # Infected files
        if scan_data.get('infected_files'):
            story.append(Paragraph('Infected Files', styles['Heading1']))
            story.append(Spacer(1, 12))
            
            infected_data = [['File Path', 'Threat']]
            for file_info in scan_data['infected_files']:
                infected_data.append([
                    file_info.get('path', ''),
                    file_info.get('threat', '')
                ])
            
            infected_table = Table(infected_data, colWidths=[3*inch, 3*inch])
            infected_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(infected_table)
            story.append(Spacer(1, 20))
    
    def _add_url_csv_data(self, writer, scan_data):
        """Add URL-specific CSV data"""
        if scan_data.get('open_ports'):
            writer.writerow(['Open Ports'])
            writer.writerow(['Port', 'Service', 'State'])
            for port_info in scan_data['open_ports']:
                writer.writerow([
                    port_info.get('port', ''),
                    port_info.get('service', ''),
                    port_info.get('state', '')
                ])
            writer.writerow([])
    
    def _add_file_csv_data(self, writer, scan_data):
        """Add file-specific CSV data"""
        hash_analysis = scan_data.get('hash_analysis', {})
        if hash_analysis:
            writer.writerow(['Hash Analysis'])
            writer.writerow(['Type', 'Value'])
            for hash_type, hash_value in hash_analysis.items():
                writer.writerow([hash_type.upper(), hash_value])
            writer.writerow([])
    
    def _add_usb_csv_data(self, writer, scan_data):
        """Add USB-specific CSV data"""
        scan_summary = scan_data.get('scan_summary', {})
        if scan_summary:
            writer.writerow(['Scan Summary'])
            writer.writerow(['Metric', 'Value'])
            for key, value in scan_summary.items():
                writer.writerow([key.replace('_', ' ').title(), value])
            writer.writerow([])
    
    def _get_recommendations(self, scan_type, scan_data):
        """Get security recommendations based on scan results"""
        recommendations = []
        
        status = scan_data.get('status', 'unknown')
        threats = scan_data.get('threats', [])
        
        if status == 'infected' or threats:
            recommendations.extend([
                'Quarantine or remove the scanned item immediately',
                'Run a full system antivirus scan',
                'Check for system compromise indicators',
                'Update security software definitions'
            ])
        
        if scan_type == 'url':
            if scan_data.get('open_ports'):
                recommendations.append('Review open ports and close unnecessary services')
            if not scan_data.get('ssl_valid', True):
                recommendations.append('Verify SSL certificate validity before entering sensitive data')
        
        elif scan_type == 'usb':
            recommendations.extend([
                'Disable USB autorun functionality',
                'Scan all removable media before use',
                'Implement USB device whitelisting',
                'Regular security awareness training for users'
            ])
        
        if not recommendations:
            recommendations.append('No immediate security actions required')
        
        recommendations.append('Continue monitoring for new threats and vulnerabilities')
        
        return recommendations
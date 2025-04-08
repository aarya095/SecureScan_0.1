import json
import os
from datetime import datetime
from fpdf import FPDF
from PyQt6.QtWidgets import QFileDialog

class ScanReportGenerator:
    """Generates a PDF security scan report using mapped data and scan results."""

    def __init__(self, parent=None, mapped_data_file="mapped_data.json", results_file="security_scan_results.json"):
        self.mapped_data_file = mapped_data_file
        self.results_file = results_file
        self.report_data = {}
        self.parent = parent  # For QFileDialog

    def load_json(self, file_path):
        """Load JSON data from a file."""
        try:
            with open(file_path, "r") as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"❌ Error loading {file_path}")
            return None

    def collect_report_data(self):
        """Collect scan details from files."""
        print("\n📌 Collecting scan details...")

        self.report_data["scan_datetime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        mapped_data = self.load_json(self.mapped_data_file)
        self.report_data["website_info"] = mapped_data.get("website_info", {}) if mapped_data else {}

        scan_results = self.load_json(self.results_file)
        self.report_data["scan_results"] = scan_results if scan_results else {}

        print("✅ Data collection complete.")

    def save_as_pdf(self, output_file):
        """Generate the PDF report."""
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", "B", 30)
        pdf.cell(200, 10, "Security Scan Report", ln=True, align="C")
        pdf.ln(10)

        # Date and time
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"Scan Date & Time: {self.report_data['scan_datetime']}", ln=True)
        pdf.ln(5)

        # Execution Times
        execution_times = self.report_data["scan_results"].get("execution_times", {})
        pdf.cell(0, 10, "Execution Times:", ln=True)
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 10, f"  - Total Scan Time: {execution_times.get('total_scan_time', 'N/A')} seconds", ln=True)
        pdf.cell(0, 10, f"  - Scanner Time: {execution_times.get('scanner_time', 'N/A')} seconds", ln=True)
        pdf.cell(0, 10, f"  - Store Time: {execution_times.get('store_time', 'N/A')} seconds", ln=True)
        pdf.ln(10)

        # Website Info
        website_info = self.report_data["website_info"]
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Website Information:", ln=True)
        pdf.set_font("Arial", "", 11)
        if website_info:
            for key, value in website_info.items():
                pdf.cell(0, 10, f"  - {key}: {str(value)}", ln=True)
        else:
            pdf.cell(0, 10, "  - No website information available.", ln=True)
        pdf.ln(10)

        # Scan Results
        scan_results = self.report_data["scan_results"].get("scans", {})
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Security Scan Results:", ln=True)

        for scanner_name, scanner_data in scan_results.items():
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, f"\n{scanner_name}", ln=True)

            for url, results in scanner_data.items():
                pdf.set_font("Arial", "I", 11)
                pdf.cell(0, 10, f"  - URL: {url}", ln=True)

                if isinstance(results, list):
                    for item in results:
                        pdf.set_font("Arial", "", 11)
                        pdf.cell(0, 10, f"    Vulnerable: {item.get('vulnerable', False)}", ln=True)
                        pdf.cell(0, 10, f"    Severity: {item.get('severity', 'N/A')}", ln=True)
                        pdf.cell(0, 10, f"    Description: {item.get('severity_description', 'No description.')}", ln=True)
                        pdf.ln(3)
                elif isinstance(results, dict):
                    for vuln_type, severity in results.items():
                        pdf.set_font("Arial", "", 11)
                        pdf.cell(0, 10, f"    {vuln_type}: {severity}", ln=True)
                    pdf.ln(3)

        pdf.output(output_file)
        print(f"📄 Report saved as PDF: {output_file}")

    def generate_report(self):
        """Generate the report and ask user for save path."""
        self.collect_report_data()

        options = QFileDialog.Options()
        options |= QFileDialog.Option.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(
            parent=self.parent,
            caption="Save PDF Report",
            filter="PDF Files (*.pdf)",
            options=options
        )

        if file_path:
            if not file_path.endswith(".pdf"):
                file_path += ".pdf"
            self.save_as_pdf(file_path)
        else:
            print("⚠️ PDF save cancelled by user.")

import json
import os
from datetime import datetime
from fpdf import FPDF

class ScanReportGenerator:
    """Generates a security scan report with website info and scan results."""

    def __init__(self, mapped_data_file="mapped_data.json", results_file="security_scan_results.json"):
        """Initialize file paths."""
        self.mapped_data_file = mapped_data_file
        self.results_file = results_file
        self.report_data = {}

    def load_json(self, file_path):
        """Load JSON data from a file."""
        try:
            with open(file_path, "r") as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"❌ Error loading {file_path}")
            return None

    def collect_report_data(self):
        """Collect all required information for the report."""
        print("\n📌 Collecting scan details...")

        # Get current date and time
        self.report_data["scan_datetime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Load website information from mapped_data.json
        mapped_data = self.load_json(self.mapped_data_file)
        if mapped_data:
            self.report_data["website_info"] = mapped_data.get("website_info", {})
        else:
            self.report_data["website_info"] = "No website information available."

        # Load scan results from security_scan_results.json
        scan_results = self.load_json(self.results_file)
        if scan_results:
            self.report_data["scan_results"] = scan_results
        else:
            self.report_data["scan_results"] = "No scan results available."

        print("✅ Data collection complete.")

    def save_as_json(self, output_file="scan_report.json"):
        """Save the report as a JSON file."""
        with open(output_file, "w") as file:
            json.dump(self.report_data, file, indent=4)
        print(f"📄 Report saved as JSON: {output_file}")

    def save_as_pdf(self, output_file="scan_report.pdf"):
        """Generate a structured and well-formatted PDF report."""
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", "B", 30)

        # Title
        pdf.cell(200, 10, "Security Scan Report", ln=True, align="C")
        pdf.ln(10)

        # Scan Date & Time
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"Scan Date & Time: {self.report_data['scan_datetime']}", ln=True)
        pdf.ln(5)

        # Execution Times
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Execution Times:", ln=True)
        pdf.set_font("Arial", "", 11)

        execution_times = self.report_data["scan_results"].get("execution_times", {})
        total_scan_time = execution_times.get("total_scan_time", "N/A")
        scanner_time = execution_times.get("scanner_time", "N/A")
        store_time = execution_times.get("store_time", "N/A")

        pdf.cell(0, 10, f"  - Total Scan Time: {total_scan_time} seconds", ln=True)
        pdf.cell(0, 10, f"  - Scanner Time: {scanner_time} seconds", ln=True)
        pdf.cell(0, 10, f"  - Store Time: {store_time} seconds", ln=True)

        pdf.ln(10)

        # Website Information
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Website Information:", ln=True)
        pdf.set_font("Arial", "", 11)
        website_info = self.report_data["website_info"]

        if isinstance(website_info, dict):
            for key, value in website_info.items():
                pdf.cell(0, 10, f"  - {key}: {str(value)}", ln=True)
        else:
            pdf.cell(0, 10, "  - No website information available.", ln=True)

        pdf.ln(10)

        # Security Scan Results
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Security Scan Results:", ln=True)
        pdf.set_font("Arial", "", 11)

        scan_results = self.report_data["scan_results"].get("scans", {})
        for scanner_name, scanner_results in scan_results.items():
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, f"\n{scanner_name}", ln=True)
            pdf.set_font("Arial", "B", 11)

            for url, vulnerabilities in scanner_results.items():
                pdf.set_font("Arial", "I", 11)
                pdf.cell(0, 10, f"  - URL: {url}", ln=True)
                pdf.set_font("Arial", "B", 11)

                if isinstance(vulnerabilities, list):  # For scanners that return lists of vulnerabilities (e.g., SQLInjectionScanner)
                    for entry in vulnerabilities:
                        pdf.set_font("Arial", "B", 11)
                        pdf.cell(0, 10, f"    Vulnerable: {entry.get('vulnerable', False)}", ln=True)
                        pdf.set_font("Arial", "B", 11)
                        pdf.cell(0, 10, f"    Severity: {entry.get('severity', 'N/A')}", ln=True)
                        pdf.cell(0, 10, f"    Description: {entry.get('severity_description', 'No description available.')}", ln=True)
                        pdf.ln(5)
                elif isinstance(vulnerabilities, dict):  # For scanners like BrokenAuthScanner
                    for vuln_type, severity in vulnerabilities.items():
                        pdf.set_font("Arial", "B", 11)
                        pdf.cell(0, 10, f"    {vuln_type}: {severity}", ln=True)
                    pdf.ln(5)

        # Save the PDF
        pdf.output(output_file)
        print(f"📄 Report saved as PDF: {output_file}")

    def generate_report(self, output_format="json"):
        """Generate the scan report in the requested format."""
        self.collect_report_data()

        if output_format.lower() == "json":
            self.save_as_json()
        elif output_format.lower() == "pdf":
            self.save_as_pdf()
        else:
            print("❌ Invalid format! Choose 'json' or 'pdf'.")

# Example Usage
if __name__ == "__main__":
    generator = ScanReportGenerator()

    # Generate and save report as JSON
    generator.generate_report(output_format="json")

    # Generate and save report as PDF
    generator.generate_report(output_format="pdf")

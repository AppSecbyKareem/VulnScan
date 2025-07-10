import os
import subprocess
import datetime
from PIL import Image, ImageDraw, ImageFont

# List of weak TLS/SSL ciphers and protocols
WEAK_TLS_INDICATORS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "EXP", "LOW", "MEDIUM", "CBC", "RC4", "3DES"]

# Path to cover image
COVER_IMAGE_PATH = "/../../TLS.png"

def run_ssl_scan(targets_file, output_pdf):
    """Runs SSL scan using Nmap and generates a PDF report with weak ciphers highlighted in red."""
    if not os.path.exists(targets_file):
        print(f"Error: {targets_file} not found!")
        return

    # Read targets from file
    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    if not targets:
        print("Error: No valid targets found in the file!")
        return

    # Get real-time date
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Run scan and collect results
    scan_results = {}
    for target in targets:
        print(f"Scanning {target}...")
        command = ["nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", "443", target]
        result = subprocess.run(command, capture_output=True, text=True)
        scan_results[target] = result.stdout if result.stdout else "No output or scan failed."

    # Generate PDF report
    create_pdf(scan_results, output_pdf, scan_date)
    print(f"Scanning completed on {scan_date}! Report saved as {output_pdf}")

def create_pdf(scan_results, output_pdf, scan_date):
    """Generate a structured TLS/SSL scan report with a cover image, summary, and scan details."""
    images = []
    strong_targets = []
    weak_targets = {}


    # **1️⃣ Add Cover Image**
    if os.path.exists(COVER_IMAGE_PATH):
        cover = Image.open(COVER_IMAGE_PATH)
        cover = cover.convert("RGB")
        cover = cover.resize((1000, 1454))  # Resize to A4
        images.append(cover)
    else:
        print("Warning: Cover image not found, skipping cover page.")

    # Load fonts
    try:
        title_font = ImageFont.truetype("Times New Roman Bold.ttf", 50)
        header_font = ImageFont.truetype("Times New Roman.ttf", 35)
        body_font = ImageFont.truetype("Times New Roman.ttf", 22)
    except:
        title_font = ImageFont.load_default()
        header_font = title_font
        body_font = title_font

    # **Classify Targets**
    for target, output in scan_results.items():
        if any(weak in output for weak in WEAK_TLS_INDICATORS):
            weak_targets[target] = [line for line in output.split("\n") if any(weak in line for weak in WEAK_TLS_INDICATORS)]
        else:
            strong_targets.append(target)

    # **1️ Cover Page**
    cover = Image.new("RGB", (1000, 1400), "white")
    draw = ImageDraw.Draw(cover)

    # Black Top Bar
    draw.rectangle([(0, 0), (1000, 200)], fill="black")
    draw.text((250, 80), "TLS/SSL Scan Report", font=title_font, fill="red")

    # Red Bottom Bar
    draw.rectangle([(0, 1250), (1000, 1400)], fill="black")
    draw.text((300, 1300), "Confidential Security Report", font=header_font, fill="red")

    # Report Details
    draw.text((100, 300), "Prepared by: Security Team", font=header_font, fill="black")
    draw.text((100, 350), f"Date: {scan_date}", font=header_font, fill="black")  # Dynamic real-time date
    draw.text((100, 400), "Report ID: TLS-SEC-2025-001", font=header_font, fill="black")
    #draw.text((100, 450), "Classification:  Confidential ", font=header_font, fill="red")
    draw.text((100, 500), "Scope: External TLS/SSL Security Assessment", font=header_font, fill="black")
    draw.text((100, 550), "Assessment Methodology: Automated & Manual Verification", font=header_font, fill="black")
    draw.text((100, 600), "Scanner Used: Nmap (ssl-enum-ciphers)", font=header_font, fill="black")

    # **Security Findings Summary**
    draw.text((100, 700), " Security Findings Summary:", font=header_font, fill="red")

    draw.text((100, 750), f"• Number of Targets Scanned: {len(scan_results)}", font=body_font, fill="black")
    draw.text((100, 800), f"• Targets with Strong Ciphers: {len(strong_targets)}", font=body_font, fill="green")
    draw.text((100, 850), f"• Targets with Weak Ciphers: {len(weak_targets)}", font=body_font, fill="red")
    draw.text((100, 900), f"• High-Risk Findings: {len([t for t in weak_targets if 'TLS 1.0' in ''.join(weak_targets[t]) or 'RC4' in ''.join(weak_targets[t])])}", font=body_font, fill="red")
    draw.text((100, 950), f"• Medium-Risk Findings: {len([t for t in weak_targets if 'CBC' in ''.join(weak_targets[t])])}", font=body_font, fill="orange")
    draw.text((100, 1000), "• Recommended Actions: Immediate Mitigation Required", font=body_font, fill="black")

    images.append(cover)

    # **2️ Summary Page**
    summary_img = Image.new("RGB", (1000, 1400), "white")
    draw = ImageDraw.Draw(summary_img)
    #draw.text((100, 80), "Report Summary", font=header_font, fill="red")

    y_position = 150

    # Strong Targets
    draw.text((100, y_position), " Strong Cipher Configuration:", font=header_font, fill="black")
    y_position += 50

    if strong_targets:
        for target in strong_targets:
            draw.text((120, y_position), f" {target}", font=body_font, fill="black")
            y_position += 30
    else:
        draw.text((120, y_position), " No strong cipher configurations found!", font=body_font, fill="black")
        y_position += 30

    y_position += 50
    draw.text((100, y_position), " Weak Ciphers/Protocols Detected:", font=header_font, fill="black")
    y_position += 50

    if weak_targets:
        for target, issues in weak_targets.items():
            draw.text((120, y_position), f" {target}:", font=body_font, fill="black")
            y_position += 30
            for issue in issues:
                draw.text((140, y_position), f" {issue.strip()}", font=body_font, fill="red")
                y_position += 25
            y_position += 20
    else:
        draw.text((120, y_position), " No weak configurations detected!", font=body_font, fill="black")

    images.append(summary_img)

    # **3️ Scan Results Pages**
    for target, output in scan_results.items():
        img = Image.new("RGB", (1000, 1400), "white")
        draw = ImageDraw.Draw(img)

        draw.text((100, 80), f"Scan Result for: {target}", font=header_font, fill="black")

        draw.rectangle([(50, 200), (950, 1350)], outline="black", width=3)

        y_position = 220
        for line in output.split("\n"):
            if y_position > 1300:
                break  # Prevent text overflow

            if any(weak in line for weak in WEAK_TLS_INDICATORS):
                draw.text((70, y_position), line, font=body_font, fill="red")
            else:
                draw.text((70, y_position), line, font=body_font, fill="black")

            y_position += 25

        images.append(img)

    images[0].save(output_pdf, save_all=True, append_images=images[1:])
    print(f"PDF saved successfully: {output_pdf}")

# Example usage
targets_file = "/../../targets.txt"
output_pdf = "/../../../ssl_scan_Month_report.pdf"
run_ssl_scan(targets_file, output_pdf)

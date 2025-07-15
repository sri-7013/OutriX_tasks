import customtkinter as ctk
import re
import socket
import ssl
import whois
import webbrowser
from datetime import datetime, UTC
from urllib.parse import urlparse
import tkinter as tk

# === Rule-based scoring system ===
def evaluate_url(url):
    score = 0
    reasons = []

    if not url.lower().startswith("https://"):
        score += 2
        reasons.append("DOES NOT USE HTTPS")
    else:
        reasons.append("USES HTTPS")

    keywords = ["login", "verify", "secure", "account", "update", "bank", "confirm", "reset", "signin"]
    found = [word for word in keywords if word in url.lower()]
    if found:
        score += 2
        reasons.append(f"SUSPICIOUS KEYWORDS FOUND: {', '.join(found).upper()}")

    trusted_brands = ["paypal", "google", "amazon", "bankofamerica", "apple", "microsoft"]
    brand_hits = [b for b in trusted_brands if b in url.lower()]
    if brand_hits and found:
        score += 2
        reasons.append(f"POSSIBLE BRAND IMPERSONATION: {', '.join(brand_hits).upper()}")

    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        score += 2
        reasons.append("USES IP ADDRESS INSTEAD OF DOMAIN")

    if re.search(r"\.(tk|xyz|cf|gq|ml|cn)\b", url):
        score += 1
        reasons.append("SUSPICIOUS DOMAIN EXTENSION DETECTED")

    for symbol in ['@', '-', '%', '=']:
        if url.count(symbol) > 2:
            score += 1
            reasons.append(f"TOO MANY '{symbol}' SYMBOLS DETECTED")

    if len(url) > 75:
        score += 1
        reasons.append("URL LENGTH IS UNUSUALLY LONG")

    return score, reasons

# === Security Enhancements ===
def extra_checks(url, reasons):
    try:
        domain = urlparse(url).netloc

        try:
            ip = socket.gethostbyname(domain)
            reasons.append(f"RESOLVES TO IP: {ip}")
        except:
            reasons.append("DNS RESOLUTION FAILED")

        if url.startswith("https://"):
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        expiry_str = cert['notAfter']
                        expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.now(UTC)).days
                        if days_left > 0:
                            reasons.append(f"SSL CERT VALID (EXPIRES IN {days_left} DAYS)")
                        else:
                            reasons.append("⚠️ SSL CERTIFICATE EXPIRED")
            except:
                reasons.append("SSL CERTIFICATE CHECK FAILED")
        else:
            reasons.append("NO SSL CERTIFICATE (NON-HTTPS URL)")

        try:
            info = whois.whois(domain)
            created = info.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                age_days = (datetime.now(UTC) - created).days
                if age_days < 180:
                    reasons.append(f"DOMAIN AGE: {age_days} DAYS (VERY NEW — SUSPICIOUS)")
                else:
                    reasons.append(f"DOMAIN AGE: {age_days} DAYS")
            else:
                reasons.append("DOMAIN AGE: UNKNOWN")
        except:
            reasons.append("WHOIS LOOKUP FAILED")

    except Exception as e:
        reasons.append(f"CHECK ERROR: {str(e).upper()}")

# === GUI ===
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

app = ctk.CTk()
app.title("LINKSHIELD - URL CHECKER")
app.geometry("720x600")
app.minsize(720, 600)  # Allow resizing

main_frame = ctk.CTkFrame(app, fg_color="transparent")
main_frame.pack(expand=True)

# === LINKSHIELD Title ===
linkshield_label = ctk.CTkLabel(main_frame, text="🔰 LINKSHIELD", font=("Segoe UI", 28, "bold"), text_color="#33FFFF")
linkshield_label.pack(pady=(20, 10))

url_var = ctk.StringVar()
entry = ctk.CTkEntry(main_frame, width=480, height=40, font=("Segoe UI", 14),
                     textvariable=url_var, placeholder_text="PASTE A URL TO SCAN...")
entry.pack(pady=(10, 10))

# === Right-click menu ===
def show_menu(event):
    menu = tk.Menu(app, tearoff=0)
    menu.add_command(label="COPY", command=lambda: app.clipboard_append(entry.get()))
    menu.add_command(label="PASTE", command=lambda: entry.insert("insert", app.clipboard_get()))
    menu.tk_popup(event.x_root, event.y_root)

entry.bind("<Button-3>", show_menu)

result_label = ctk.CTkLabel(main_frame, text="", font=("Segoe UI", 16, "bold"))
result_label.pack(pady=5)

scan_msg = ctk.CTkLabel(main_frame, text="", font=("Segoe UI", 14, "italic"))
scan_msg.pack()

# === Suggestion label + textbox (resized smaller) ===
suggestion_label = ctk.CTkLabel(main_frame, text="SECURITY INSIGHTS", font=("Segoe UI", 15, "bold"))
suggestion_label.pack()

suggestion_box = ctk.CTkTextbox(main_frame, width=460, height=110, font=("Segoe UI", 13), corner_radius=12)
suggestion_box.pack(pady=(5, 20))
suggestion_box.configure(state="disabled")

# === SCAN Logic ===
def scan(event=None):
    url = url_var.get().strip()
    if not url or not url.startswith(("http://", "https://")):
        result_label.configure(text="PLEASE ENTER A VALID URL", text_color="orange")
        open_button.configure(state="disabled")
        return

    scan_msg.configure(text="🔄 SCANNING...", text_color="yellow")
    app.update_idletasks()

    score, reasons = evaluate_url(url)
    extra_checks(url, reasons)

    if score <= 2:
        result = "✅ SAFE"
        color = "#2ecc71"
    elif 3 <= score <= 4:
        result = "⚠️ SUSPICIOUS"
        color = "#f39c12"
    else:
        result = "❌ PHISHING"
        color = "#e74c3c"

    result_label.configure(text=result, text_color=color)
    scan_msg.configure(text="")

    suggestion_box.configure(state="normal")
    suggestion_box.delete("0.0", "end")
    for reason in reasons:
        suggestion_box.insert("end", f"• {reason}\n")
    suggestion_box.configure(state="disabled")

    suggestion_label.configure(text="SECURITY INSIGHTS")

    if result == "✅ SAFE":
        open_button.configure(state="normal")
    else:
        open_button.configure(state="disabled")

# === Clear logic ===
def clear():
    url_var.set("")
    result_label.configure(text="", text_color="white")
    scan_msg.configure(text="")
    open_button.configure(state="disabled")
    suggestion_box.configure(state="normal")
    suggestion_box.delete("0.0", "end")
    suggestion_box.configure(state="disabled")
    suggestion_label.configure(text="SECURITY INSIGHTS")

# === Buttons ===
button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
button_frame.pack(pady=10)

scan_button = ctk.CTkButton(button_frame, text="SCAN", command=scan, width=160, height=40, corner_radius=18)
scan_button.grid(row=0, column=0, padx=8)

open_button = ctk.CTkButton(button_frame, text="🌐 OPEN", command=lambda: webbrowser.open(url_var.get().strip()),
                             width=100, height=40, corner_radius=18, state="disabled")
open_button.grid(row=0, column=1, padx=8)

clear_button = ctk.CTkButton(button_frame, text="🧹 CLEAR", command=clear, width=100, height=40, corner_radius=18)
clear_button.grid(row=0, column=2, padx=8)

entry.bind("<Return>", scan)

# === Footer ===
footer = ctk.CTkLabel(main_frame, text="🔰 LINKSHIELD | DEVELOPED BY SRIKAR",
                      font=("Segoe UI", 12, "bold"))
footer.pack(pady=(0, 10))

app.mainloop()

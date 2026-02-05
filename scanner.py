import ipaddress 
#A fast, lightweight IPv4/IPv6 manipulation library in Python.This library is used to create/poke/manipulate IPv4 and IPv6 addresses and networks.
import socket #This module provides socket operations and some related functions. On Unix, it supports IP (Internet Protocol) and Unix domain sockets.
from datetime import datetime

print("---------------------")
print("Beginner Network Scanner")
print("---------------------")


choice = input("Choose scan type: \n1. IP & Port Scan \n2. URL Phishing Scan \nEnter choice(1/2): ")

report_lines= []
report_lines.append("Beginner Network Scanner Report\n")
report_lines.append(f"Scan TIme: {datetime.now()}\n\n")


#----------------------- IP & PORT SCAN -----------------------
if choice == "1":
    target_ip = input("Enter the target IP Address: ")
    report_lines.append(f"Target IP: {target_ip}\n")


    try: 
        ip=ipaddress.ip_address(target_ip) #python_module.function(string) = returns if the string is of the correct type or not.
        
        print("\nValid IP address")
        report_lines.append("Valid IP Address\n")


        #check IP type
        if ip.is_loopback:
            ip_type= "Loopback IP"
            risk ="NONE"
        elif ip.is_private: #(property) is_private: bool
            ip_type= "Private IP"
            risk ="LOW"
        elif ip.is_multicast:
            ip_type= "Multicast IP"
            risk ="LOW"
        else:
            ip_type= "Public IP"
            risk ="HIGH"
        
        print(f"Type: {ip_type}\n")
        print(f"Risk: {risk}\n")

        report_lines.append(f"Type: {ip_type}\n")
        report_lines.append(f"Risk: {risk}\n")


        print("\nScanning common ports...\n")
        report_lines.append("Port Scan Results:\n")

        common_ports = {
        21: "FTP",       # File Transfer Protocol – used to transfer files between client and server
        22: "SSH",       # Secure Shell – used for secure remote login and command execution
        23: "Telnet",    # Telecommunication Network – remote login (insecure, unencrypted)
        25: "SMTP",      # Simple Mail Transfer Protocol – used for sending emails
        53: "DNS",       # Domain Name System – translates domain names into IP addresses
        80: "HTTP",      # HyperText Transfer Protocol – standard web traffic (unencrypted)
        110: "POP3",     # Post Office Protocol v3 – used to receive emails from a server
        143: "IMAP",     # Internet Message Access Protocol – email retrieval while keeping mail on server
        443: "HTTPS",    # HyperText Transfer Protocol Secure – encrypted web traffic
        3306: "MySQL",   # MySQL Database Service – database communication port
        3389: "RDP",     # Remote Desktop Protocol – remote graphical login to Windows systems
        8080: "HTTP-ALT" # HyperText Transfer Protocol (Alternate) – proxy / dev web servers
    }

        for port, service in common_ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Creates a network connection attempt
            s.settimeout(0.5) #prevents hanging

            result = s.connect_ex((target_ip, port)) #connect_ex -> Tries connecting, Returns 0 if OPEN and Returns error if CLOSED       
            if result == 0:
                output = f"Port {port} ({service} is OPEN)"
            else:
                output=  f"Port {port} ({service} is CLOSED)"

            print(output)
            report_lines.append(output + "\n")

            s.close()

    except ValueError: #(Class) Inappropriate argument value (of correct type).
        print("\n Invalid IP Address")
        report_lines.append("Invalid IP address\n")
#---------------------- URL PHISHING SCAN -------------------------
elif choice == '2':
    url = input("\nEnter URL to analyze: ")
    report_lines.append(f"Target URL: {url}\n\n")

    risk_score = 0
    reasons =[]

    if not url.startswith("https://"):
        risk_score += 1
        reasons.append("HTTPS not detected")
    if len(url) > 75:
        risk_score += 1
        reasons.append("URL length is unusually long")

    suspicious_words= [
        "login", "verify", "bank", "secure",
        "account", "update", "free", "confirm"
    ]

    for word in suspicious_words:
        if word in url.lower():
            risk_score += 1
            reasons.append(f"Suspicious keyword detected: {word}")
    
    try: 
        ipaddress.ip_address(url.replace("https://", "").replace("http://", ""))
        risk_score += 2
        reasons.append("IP address used instead of domain")
    except:
        pass

    print("\nURL Analysis Result: ")
    print(f"Risk Score: {risk_score}")

    if risk_score >= 4:
         verdict = "HIGH RISK (Possible Phishing)"
    elif risk_score >= 2:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    print(f"Verdict: {verdict}")

    report_lines.append(f"Risk Score: {risk_score}\n")
    report_lines.append(f"Verdict: {verdict}\n\n")
    report_lines.append("Reasons:\n")

    for r in reasons: 
        report_lines.append("- " + r + "\n")

else: 
    print("Invalid choice")
#----------------------to save report-----------------------------

with open("scan_report.txt", "w") as file: #with open("file_name", "w") creates the file, writes onto it and closes it.
    file.writelines(report_lines)
print('\nScan report saved as scan_report.txt')

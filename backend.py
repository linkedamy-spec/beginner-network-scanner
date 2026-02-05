from flask import Flask, request, jsonify, render_template

from flask_cors import CORS
import ipaddress, socket
import re

#Create the Flask application
#__name__ tells Flask  where this file is located
app = Flask(__name__)
#Allow requests from frontend running on a different port(CORS)
CORS(app)

@app.route("/") 
def home(): 
    """
    Health-check route.
    Used to verify that the backend server is running.
    """
    return render_template("index.html")

@app.route("/scan-url", methods=["POST"]) 
def scan_url():
    """
    Receives a URL from the frontend,
    analyzes it for phishing indicators,
    and returns a risk verdict with reasons.
    """
    data = request.get_json() #reads JSON data sent from JavaScript    
    url = data["url"].lower() #Convert URL to lowercase for consistent checks

    risk = 0 # Risk score counter
    reasons = []  # Stores reasons contributing to risk

# 1. Check if HTTPS is missing
    if not url.startswith("https://"):
        risk += 1
        reasons.append("HTTPS NOT DETECTED")
    
# 2. Check for unusually long URLs
    if len(url) >75:
        risk +=1
        reasons.append("URL length is unusually long")

# 3. Check for common phishing keywords
    suspicious_words= [
       "login", "verify", "bank", "free",
        "secure", "paypal", "account", "confirm", "upi" 
    ]

    for word in suspicious_words:
        if word in url:
            risk += 1
            reasons.append(f"Suspicious keyword detected: {word}")
            break #stop after first match

# 4. Detect IP-based URLs instead of domain names
    ip_pattern = r"\b\d{1,3}(\.\d{1,3}){3}\b"
    if re.search(ip_pattern, url):
        risk += 1
        reasons.append("IP-based URL detected instead of domain")

# Determine final verdict based on risk score  
    if risk == 0:
        verdict = "SAFE"
        color = "lightgreen"
    elif risk == 1:
        verdict = "SUSPICIOUS"
        color = "gold"
    else:
        verdict = "HIGH RISK"
        color = "red"
   
    
    return jsonify({
        "verdict": verdict,
        "risk": risk,
        "reasons": reasons,
        "color": color
    })

@app.route("/analyze-ip", methods=["POST"])
def analyze_ip():
    """
    Receives an IP address from the frontend,
    analyzes its type and exposure risk,
    and returns the analysis as JSON.
    """
    data= request.get_json() # Get JSON data sent from frontend (fetch / axios)
    target_ip=data["ip"]# Extract the IP address entered by the user

    try: 
        # Validate and convert the IP address
        # This will raise ValueError if IP is invalid
        ip = ipaddress.ip_address(target_ip)

# Determine IP type and exposure risk
        if ip.is_loopback:
            ip_type = "Loopback IP"
            risk = "NONE"
        elif ip.is_private:
            ip_type = "Private IP"
            risk = "LOW"
        else:
            ip_type = "Public IP"
            risk = "HIGH"
        open_ports = []
        closed_ports=[]

        common_ports = {
             21: "FTP",
            22: "SSH",
            80: "HTTP",
            443: "HTTPS"
        }
        # Scan each port 
        for port, service in common_ports.items():
             # Create TCP socket
            s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            s.settimeout(0.5)  # Timeout so scan doesn't hang

            # connect_ex returns 0 if connection succeeds
            result = s.connect_ex((target_ip, port))

             # closing the socket
            s.close()

            if result == 0:
                open_ports.append(f"{port} ({service})")
            else:
                closed_ports.append(f"{port} ({service})")
                
        return jsonify({
            "ip_type": ip_type,
            "risk": risk,
            "open_ports": open_ports,
            "closed_ports": closed_ports
        })

    except ValueError:
        return jsonify({
            "error": "Invalid IP address"
        })

   
if __name__=="__main__": 
# Start the Flask development server
    app.run(host="0.0.0.0", port=10000) 
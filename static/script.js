// Base URL of deployed backend
const BASE_URL = "https://beginner-network-scanner.onrender.com";

//phishing website checker
async function checkURL() {
  const url = document.getElementById("urlInput").value;
  const result = document.getElementById("result");

  if (url === "") {
    result.innerText = " Please enter a URL";
    result.style.color = "gold";
    return;
  }

  const response = await fetch(`${BASE_URL}/scan-url`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  });

  const data = await response.json();

  let reasonsHTML = "";
  for (let r of data.reasons) {
    reasonsHTML += `• ${r}<br>`;
  }

  result.style.color = data.color;
  result.innerHTML = `
    <strong>${data.verdict}</strong><br><br>
    ${reasonsHTML}
  `;
}

// IP analyzer (backend-powered)
async function analyzeIP() {
  const ip = document.getElementById("ipInput").value;
  const result = document.getElementById("ipResult");

  if (ip === "") {
    result.innerText = "Please enter an IP address";
    result.style.color = "gold";
    return;
  }

  const response = await fetch(`${BASE_URL}/analyze-ip`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ ip }),
  });

  const data = await response.json();

  if (data.error) {
    result.innerText = data.error;
    result.style.color = "red";
    return;
  }

  let openPortsHTML = "";
  for (let p of data.open_ports) {
    openPortsHTML += `• ${p}<br>`;
  }

  let closedPortsHTML = "";
  for (let p of data.closed_ports) {
    closedPortsHTML += `• ${p}<br>`;
  }

  result.innerHTML = `
    Valid IP Address<br>
    <strong>Type:</strong> ${data.ip_type}<br>
    <strong>Risk:</strong> ${data.risk}<br><br>

    <strong>Open Ports:</strong><br>
    ${openPortsHTML || "None"}<br><br>

    <strong>Closed Ports:</strong><br>
    ${closedPortsHTML}
  `;

  result.style.color = "lightgreen";
}

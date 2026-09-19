(() => {
  const form = document.getElementById("wifi-form");
  const ssid = document.getElementById("ssid");
  const password = document.getElementById("password");
  const button = document.getElementById("submit");
  const status = document.getElementById("status");

  const setStatus = (message, kind = "") => {
    status.textContent = message;
    status.className = `status ${kind}`.trim();
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setStatus("Saving Wi-Fi settings…");
    button.disabled = true;

    try {
      const ssidValue = ssid.value;
      const passwordValue = password.value;
      const ssidBytes = new TextEncoder().encode(ssidValue).length;
      const passwordBytes = new TextEncoder().encode(passwordValue).length;
      if (ssidBytes < 1 || ssidBytes > 32) {
        throw new Error("SSID must be 1–32 bytes long.");
      }
      if (passwordBytes !== 0 && (passwordBytes < 8 || passwordBytes > 63)) {
        throw new Error("Wi-Fi passwords must be 8–63 characters, or empty for an open network.");
      }

      const response = await fetch("/api/wifi/provision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ssid: ssidValue, password: passwordValue }),
        credentials: "same-origin",
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Could not save Wi-Fi settings.");

      setStatus("Saved! The ESP32 is rebooting now. Connect your device back to the normal network, then open the ESP-JS OS address.", "ok");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Could not save Wi-Fi settings.", "error");
      button.disabled = false;
    }
  });
})();

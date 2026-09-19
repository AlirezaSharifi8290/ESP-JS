# ESP-JS OS

A small, web-managed JavaScript application runtime for the **ESP32**.

ESP-JS OS combines a C/C++ system core with the [Elk](https://github.com/cesanta/elk) embedded JavaScript engine, a LittleFS-backed app store, and a browser-based editor. Upload, edit, run, stop, and delete JavaScript apps from a browser over Wi-Fi — without reconnecting the ESP32 to your computer just to change an app.

> **What “OS” means here:** ESP-JS OS is an OS-like application host/runtime, not a general-purpose operating system. The ESP-IDF/FreeRTOS system remains underneath it.

---

## ✨ Features

### 🧩 JavaScript apps on the ESP32

- Store multiple JavaScript apps in **LittleFS**.
- Create, edit, save, run, stop, and delete apps from the web interface.
- Apps are kept as `main.js` files under `/apps/<name>/`.
- Each saved app gets a small `manifest.json` generated automatically.
- App names may contain letters, digits, `-`, and `_`, with a maximum length of 32 characters.
- The current storage implementation can list up to **64 apps**.
- Only **one JavaScript app runs at a time** by design.

### 🖥️ Browser-based IDE

- Built-in JavaScript editor served directly by the ESP32.
- Local browser drafts using `localStorage`, so unsaved edits can survive a page refresh.
- `Ctrl+S` / `Cmd+S` saves the current app.
- `Ctrl+Enter` / `Cmd+Enter` runs the current app.
- Responsive layout for different screen sizes.
- Live device telemetry:
  - free heap
  - minimum free heap
  - uptime
  - currently running app
  - stop-request state
- Background status polling slows from **2 seconds to 5 seconds** while the browser tab is hidden.

### 🔌 Native hardware API for JavaScript

The current JS bridge exposes:

```javascript
print(value)

gpio_mode(pin, "input" | "input_pullup" | "input_pulldown" | "output")
gpio_write(pin, true_or_false)
gpio_read(pin)

delay_ms(milliseconds)
app_should_stop()
millis()
```

Example:

```javascript
gpio_mode(2, "output");

for (let i = 0; i < 10; i = i + 1) {
  gpio_write(2, true);
  if (!delay_ms(250)) break;

  gpio_write(2, false);
  if (!delay_ms(250)) break;
}

print("blink finished");
```

`delay_ms()` checks the runner stop flag in 50 ms slices, and apps can explicitly poll `app_should_stop()` for cooperative cancellation.

### 📡 Wi-Fi provisioning

Wi-Fi credentials are **not compiled into the firmware**.

On first boot, or when the saved network cannot be reached within the connection attempt, the ESP32 can start a protected provisioning access point:

```text
ESP-JS-OS-XXXXXX
```

The SSID is derived from the device's Wi-Fi MAC address. A per-device **12-character hexadecimal WPA2-PSK password** is generated and stored in NVS.

The provisioning page is available at:

```text
http://192.168.4.1/
```

After Wi-Fi credentials are submitted, they are stored through the ESP-IDF Wi-Fi configuration system and the device reboots. The project enables Wi-Fi NVS storage, so the saved station configuration persists across reboots.

### 🔐 Password-protected web portal

The normal web console is protected by a first-boot authentication flow.

- On an unconfigured device, a **256-bit (32-byte) setup secret** is generated and represented as a 64-character hexadecimal setup code.
- While authentication is unconfigured, the setup code is printed to the serial log at boot.
- The setup code is used for a one-time challenge/response proof rather than being submitted directly as the new password.
- After setup succeeds, the setup secret and its setup salt are erased from NVS, making the setup code invalid.
- User passwords must contain at least **8 characters** and may be up to **128 characters**.
- The browser derives the password verifier with **PBKDF2-HMAC-SHA-256 using 600,000 iterations**.
- Browser-side PBKDF2/HMAC is implemented through the bundled WebAssembly worker, with a Web Crypto fallback when available.
- Login and setup use one-time server challenges with HMAC proofs.
- Server-side sessions are stored only in RAM.
- Session cookies are `HttpOnly`, `SameSite=Strict`, and have a 12-hour maximum age.
- Sessions use a **12-hour inactivity timeout** on the ESP32 side.
- Rebooting the ESP32 invalidates all server-side sessions because the session tokens are not persisted.
- Up to **4 sessions** are tracked simultaneously; a new session can replace the oldest active slot when all slots are occupied.
- **5 failed login proofs** trigger a **30-second** global lockout.
- The authenticated portal supports password changes; the current session remains valid while other sessions are invalidated.
- There is intentionally no unauthenticated HTTP password-reset endpoint.

### 🛡️ Web security hardening

The HTTP server adds several browser security headers, including:

- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`
- `Cache-Control`

API responses use `no-store`, while static assets are served with revalidation disabled.

The project also restricts the browser policy to same-origin scripts/connections and disables framing, plugins, camera, microphone, and geolocation access for the web UI.

### 🧠 Race-safe app control

The runner protects its running-app state with synchronization so web requests cannot freely race the runner's start/stop state.

If an app is currently running, deleting that same app is rejected instead of removing its files underneath the running task.

### 💾 Filesystem-backed apps

The LittleFS image contains the initial app examples and browser assets:

```text
littlefs/
├── apps/
│   ├── hello/
│   │   ├── main.js
│   │   └── manifest.json
│   └── blink/
│       ├── main.js
│       └── manifest.json
└── www/
    ├── index.html
    ├── style.css
    ├── app.js
    ├── crypto-worker.js
    └── crypto.wasm
```

The web frontend is therefore stored as filesystem data instead of being compiled into a giant C string.

---

## 🏗️ Architecture

```text
                         Browser
                            │
                         HTTP / LAN
                            │
                            ▼
┌─────────────────────────────────────────────────┐
│                     ESP32                       │
│                                                 │
│  ┌───────────────┐      ┌───────────────────┐  │
│  │ Wi-Fi / HTTP  │──────│ Auth + API layer  │  │
│  │    server     │      └───────────────────┘  │
│  └───────────────┘                │             │
│                                   ▼             │
│                        ┌───────────────────┐    │
│                        │ App storage /      │    │
│                        │ LittleFS          │    │
│                        └───────────────────┘    │
│                                   │             │
│                                   ▼             │
│                        ┌───────────────────┐    │
│                        │ JavaScript runner │    │
│                        │   + Elk engine   │    │
│                        └─────────┬─────────┘    │
│                                  │              │
│                                  ▼              │
│                        Native ESP32 APIs       │
│                        GPIO / timing / etc.    │
└─────────────────────────────────────────────────┘
```

The runner creates a dedicated FreeRTOS task for the selected JavaScript app. The current implementation intentionally runs **one app at a time** rather than attempting to run multiple Elk interpreters concurrently.

---

## 📦 Flash / partition layout

The project defaults to a **4 MB flash** layout and provides a custom partition table:

| Partition | Offset | Size |
|---|---:|---:|
| `nvs` | `0x9000` | `0x6000` (24 KiB) |
| `phy_init` | `0xF000` | `0x1000` (4 KiB) |
| `factory` | `0x10000` | `0x180000` (1.5 MiB) |
| `littlefs` | `0x190000` | `0x270000` (2.4375 MiB) |

The provided partition table occupies the full 4 MiB address range from `0x000000` through `0x400000`.

The build is therefore intended for a compatible classic-ESP32-style **4 MB flash configuration**. Do not assume this exact partition map is suitable for another ESP32-family chip or a board with a different flash size.

---

## ⚙️ Project configuration

The project exposes these settings through `menuconfig`:

| Setting | Default | Range |
|---|---:|---:|
| HTTP server port | `80` | `1–65535` |
| JavaScript arena | `24576` bytes | `4096–65536` |
| Maximum JS source size | `32768` bytes | `1024–65536` |
| Maximum HTTP body | `32768` bytes | `1024–65536` |
| JS runner task stack | `12288` bytes | `8192–24576` |

The project also enables:

- 4 MB flash size configuration
- size-oriented compiler optimization
- a 1000 Hz FreeRTOS tick rate
- up to 16 LWIP sockets
- Wi-Fi NVS storage
- Wi-Fi SoftAP support
- the custom partition table

---

## 🧪 Elk JavaScript

ESP-JS OS uses [Elk](https://github.com/cesanta/elk) as its embedded JavaScript engine.

Elk intentionally implements a **small subset of JavaScript**, so ESP-JS OS is not a miniature browser/Node.js environment. In the current UI and examples:

- use `let` rather than relying on `const`/`var`
- terminate statements with semicolons
- do not expect the normal browser/Node.js standard library
- use the ESP-JS OS native functions for hardware access and timing

The project fetches Elk source through `tools/fetch_elk.ps1` or `tools/fetch_elk.sh`.

### Fetch Elk

**Windows PowerShell:**

```powershell
.\tools\fetch_elk.ps1
```

**Linux/macOS:**

```bash
./tools/fetch_elk.sh
```

The fetch script currently retrieves `elk.c` and `elk.h` from the upstream `master` branch. The script labels that source as a **3.0.0 master snapshot**.

For reproducible releases, pin an exact upstream commit rather than depending on a moving branch.

---

## 🔒 GPIO safety rules

The current JavaScript GPIO layer deliberately blocks some classic ESP32 GPIOs:

- GPIO **6–11** are rejected for output because they are associated with the ESP32 flash interface.
- GPIO **34–39** can be read, but the JS layer rejects them for output because they are input-only on the classic ESP32 target.

These rules are written specifically around the project's classic ESP32 assumptions. They should be reviewed before porting the runtime to a different chip family.

---

## 📦 Prebuilt firmware releases

You do **not** need to compile ESP-JS OS yourself to use a published release. Published releases provide a prebuilt, merged firmware binary in the GitHub **Releases** section.

Look under the release's **Assets** for:

```text
ESP-JS-AIO.bin
```

For the current 4 MB classic-ESP32 release image, the merged binary is intended to be flashed at **offset `0x0`**. It contains the firmware image and the project's flash layout/data required by the release, so you do not need to manually flash the individual bootloader, partition-table, application, and LittleFS binaries. Espressif's esptool documentation supports flashing a merged binary at `0x0`.

Example with `esptool`:

```bash
esptool --chip esp32 write-flash 0x0 ESP-JS-AIO.bin
```

> **Important:** Only flash a release image to a board matching that release's documented target and flash layout. The current project targets the **classic ESP32 with 4 MB flash**.

## 🚀 Build

### Requirements

- ESP32-compatible development board with a compatible **4 MB flash** layout
- ESP-IDF **6.x** development environment
- Python environment used by ESP-IDF
- Git / network access for the Elk fetch step
- A serial connection for flashing and first-boot setup

### 1. Clone the repository

```bash
git clone https://github.com/AlirezaSharifi8290/ESP-JS.git

cd esp-js-os
```

### 2. Fetch Elk

**Windows:**

```powershell
.\tools\fetch_elk.ps1
```

**Linux/macOS:**

```bash
./tools/fetch_elk.sh
```

### 3. Select the target

```bash
idf.py set-target esp32
```

### 4. Configure / reconfigure

```bash
idf.py reconfigure
```

Use:

```bash
idf.py menuconfig
```

to change the project-specific settings described above.

### 5. Build

```bash
idf.py build
```

### 6. Flash and monitor

Replace `COM5` with your serial port:

```bash
idf.py -p COM5 flash monitor
```

---

## 📶 First boot / Wi-Fi setup

1. Flash the firmware and open the serial monitor.
2. If no Wi-Fi credentials are stored, the ESP32 starts its protected provisioning AP.
3. Connect to the printed `ESP-JS-OS-XXXXXX` network using the printed AP password.
4. Open:

   ```text
   http://192.168.4.1/
   ```

5. Enter the target Wi-Fi SSID and password.
6. The ESP32 saves the station configuration and reboots.
7. Open the IP address reported by the ESP32 on your normal Wi-Fi network.
8. On an unconfigured device, the serial monitor also shows the first-boot authentication setup code.
9. Enter that setup code in the portal and create the permanent web-console password.

### Wi-Fi recovery behavior

If the saved Wi-Fi network cannot be reached during startup, the firmware falls back to the protected provisioning AP instead of permanently waiting for the missing network.

The provisioning AP password is generated once per device and stored in NVS, so recovery boots reuse the same AP password until the device's persistent storage is erased.

---

## 🔑 Authentication flow

At a high level:

```text
First boot
   │
   ├─ ESP32 creates setup secret
   │
   └─ Serial prints 64-char hex setup code
            │
            ▼
Browser requests challenge
            │
            ▼
Browser proves setup secret via HMAC
            │
            ▼
Browser derives password verifier
PBKDF2-HMAC-SHA256 / 600,000 iterations
            │
            ▼
ESP32 stores:
  • salt
  • iteration count
  • derived verifier
            │
            ▼
Setup secret is erased
            │
            ▼
Future logins use the stored verifier + fresh challenge
            │
            ▼
RAM session token + HttpOnly cookie
```

### Important HTTP limitation

The project currently serves the web UI over **plain HTTP**, not HTTPS.

The authentication protocol therefore does **not** make the network transport confidential or tamper-proof. An attacker able to interfere with the HTTP connection could still modify traffic or steal an authenticated session.

Treat the web server as a **trusted-LAN service** in its current form. Do not expose it directly to the public Internet.

The challenge/response design prevents a captured login proof from simply being replayed against a fresh challenge, but it does not replace TLS.

---

## 💾 App storage

Apps are stored like this:

```text
/littlefs/apps/<app-name>/
├── main.js
└── manifest.json
```

The manifest generated by the current implementation looks like:

```json
{
  "name": "blink",
  "version": "1.0.0",
  "entry": "main.js"
}
```

The current web API only executes `main.js`; the manifest is metadata for the stored app rather than a separate execution system.

---

## 🔌 HTTP API overview

The web UI talks to a small REST-style API.

### Authentication

```text
GET  /api/auth/info
GET  /api/auth/setup-challenge
POST /api/auth/setup
GET  /api/auth/challenge
POST /api/auth/login
GET  /api/auth/me
POST /api/auth/logout
GET  /api/auth/password-info
POST /api/auth/change-password
```

### Wi-Fi provisioning

```text
POST /api/wifi/provision
```

### Apps / runner

```text
GET    /api/apps
GET    /api/app?name=<name>
POST   /api/app?name=<name>
DELETE /api/app?name=<name>

POST   /api/run?name=<name>
POST   /api/stop
GET    /api/status
```

The normal app-management endpoints require an authenticated session.

---

## 🗂️ Repository structure

```text
.
├── CMakeLists.txt
├── sdkconfig.defaults
├── partitions/
│   └── partitions.csv
├── components/
│   └── elk/
│       └── CMakeLists.txt
├── data/
│   ├── apps/
│   │   ├── hello/
│   │   └── blink/
│   └── www/
│       ├── index.html
│       ├── style.css
│       ├── app.js
│       ├── crypto-worker.js
│       └── crypto.wasm
├── main/
│   ├── main.c
│   ├── auth.c / auth.h
│   ├── wifi.c / wifi.h
│   ├── storage.c / storage.h
│   ├── runner.c / runner.h
│   ├── web.c / web.h
│   ├── Kconfig.projbuild
│   └── idf_component.yml
└── tools/
    ├── fetch_elk.ps1
    ├── fetch_elk.sh
    ├── build_crypto_wasm.ps1
    ├── build_crypto_wasm.sh
    └── crypto/
        └── crypto_wasm.c
```

---

## 🧪 Included examples

### `hello`

```javascript
print("Hello from ESP-JS OS");
print(millis());
```

### `blink`

Blinks GPIO 2 ten times with cooperative stop handling.

---

## 🔧 Browser crypto module

The repository includes a prebuilt `data/www/crypto.wasm` module.

The source for it lives in:

```text
tools/crypto/crypto_wasm.c
```

To rebuild it, use:

**Windows PowerShell:**

```powershell
.\tools\build_crypto_wasm.ps1
```

**Linux/macOS:**

```bash
./tools/build_crypto_wasm.sh
```

These scripts expect a `clang` toolchain with WebAssembly target support.

---

## ⚠️ Security and trust model

ESP-JS OS is intended for **trusted code on a trusted network**.

JavaScript apps are not a security sandbox. An uploaded app receives the native APIs exposed by the runner, including GPIO access. Elk is an embedded JavaScript engine, not a browser security boundary.

The project intentionally does not attempt to provide:

- multi-tenant application isolation
- HTTPS/TLS yet
- secure-boot enforcement
- encrypted firmware distribution
- sandboxed JavaScript permissions
- cloud authentication

For a production/remote-access deployment, those concerns need to be addressed separately.

The upstream Elk project is dual-licensed under AGPLv3 or a commercial license. Review its licensing terms before distributing this project in a way that includes Elk. See the upstream [Elk license](https://github.com/cesanta/elk/blob/master/LICENSE).

---

## 🛣️ Possible future work

The current architecture leaves room for features such as:

- WebSocket-based live app logs
- app version history and rollback
- per-app capability/permission declarations
- I2C / SPI / ADC / PWM / UART APIs
- IR / RF helper APIs
- scheduled or event-driven app launches
- crash counters and automatic recovery
- firmware OTA updates with rollback
- a device settings page
- richer runtime telemetry
- multi-device management

These are **future ideas**, not current features.

---

## 📜 License

The **original ESP-JS OS source code** in this repository is licensed under the [MIT License](LICENSE).

ESP-JS OS also uses third-party components with their own licenses. In particular, **Elk is dual-licensed under AGPLv3 or a commercial license** and is fetched by the build scripts from the upstream project. The root MIT license does **not** relicense Elk. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for the dependency notices and upstream license references.

> **Distribution note:** a firmware image that includes Elk is not automatically an MIT-only work. Choose and comply with the applicable Elk licensing terms when distributing firmware or other builds that include Elk.

---

## 🙌 Why this project exists

The goal is simple: make the ESP32 feel a little less like a board you constantly have to plug into a PC, and a little more like a tiny networked computer where you can write and manage small hardware programs from a browser.

**Write JavaScript → save it → run it on the ESP32.** 🚀

## 🙏 Acknowledgments

Special thanks to @sanyar-dev for their help, suggestions, and contributions during the development of ESP-JS-OS.

Thank you for taking the time to help improve the project! ❤️
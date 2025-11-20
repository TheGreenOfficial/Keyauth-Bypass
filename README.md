# Keyauth-Bypass

A Python-based MITM proxy solution engineered to neutralize Keyauth authentication flows. The proxy intercepts and reshapes outbound/inbound traffic, enforcing predefined credentials and app metadata.

---

## 🚀 Quick Start

### **Prerequisites**
- Windows OS  
- Python **3.7+**  
- **Proxyfier**  
- **mitmproxy**

---

## ⚙️ Installation & Setup

### **1. Install mitmproxy**
```bash
pip install mitmproxy
```

### **2. Install mitmproxy Certificates**
1. Run `mitmweb` once — this generates cert files.  
2. Navigate to:  
   ```
   /cert
   ```  
3. Install `mitmproxy-ca-cert.pem` into:  
   **Windows Trusted Root Certification Authorities**

### **3. Configure Proxyfier**
- Set the target executable to use an HTTPS proxy 
- **Proxy:** `127.0.0.1`  
- **Port:** `6969`

### **4. Run the Bypass**
```bash
mitmdump -s authbypass.py --listen-port 6969 //use mitmweb to see in vervose mode in web in real time.
```

---

## 🔧 How It Works

`authbypass.py` operates as a MITM layer that dynamically rewrites Keyauth traffic.

### **Request Manipulation**
- **Init Requests:** Injects custom app name, owner ID, and version  
- **Login Requests:** Forces predefined username + password  
- **Session Handling:** Captures & auto-injects session IDs

### **Response Manipulation**
- Normalizes app metadata across responses  
- Overrides authentication responses using predefined values  
- Maintains persistent session continuity

### **Predefined Credentials**
- **Username:** `TheGreen`  
- **Password:** `xxx`  
- **App Name:** `Sangampaudel999's Application`  
- **Owner ID:** `tTsZ5ZpwTh`

---

## 📁 File Structure
```
keyauth-bypass/
├── authbypass.py          # Main MITM proxy script
└── cert/                  # mitmproxy certificates (created after first run)
```

---

## 🎯 Usage
1. Launch Proxyfier with the configured proxy  
2. Start mitmproxy using the command above  
3. Launch your target application  
4. Use any login credentials — the proxy will rewrite them automatically  

You're in. 🎉

---

### 🚨 Exceptions & Research Notes

- When experimenting with full‑system HTTPS interception, exclude essential service ports (e.g., DNS and similar baseline network services) to prevent breaking name resolution and platform connectivity.  
- Recent Keyauth builds include client‑side verification layers. For research purposes, analysts typically focus on understanding how these checks operate, since client‑side response validation mechanisms evolve frequently.  
- Behavior may vary across builds; stability isn’t guaranteed. Skilled researchers often explore multiple traffic‑analysis techniques across PE files or Android emulators to study how different clients communicate with remote authentication services.  
- The same traffic‑inspection methodology applies across various licensing or authentication workflows. Many analysts overlook client‑side HTTP(S) telemetry, but studying it can reveal how integrations function internally.  
- Contributions to this repository are welcome—especially around expanding research utilities or documenting new discoveries. Peace out for now...  


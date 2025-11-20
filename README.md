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

### **Exceptions: **
- If you are doing whole system https traffic redirrect to mitmproxy then leave some ports like DNS ports so it resolves hostnames and some others where there i forgot...
- By this time keyauth have added exe side checking of responses or something like that so you have to patch the part that is checking and its really easy...
- And it works but not all the time but ya if you are skilled enough you can make it work and login throuh any exe using keyauth or any apk inside emulator using keyauth using the same techneque forwarwing http traffic of android emulator to our win mitm-proxy as we did with PE...
- Further you can use the same techneque with liscense auth and nother auth nobody thigns of capturing exe http traffic that is validating things from online jsut research a little and you will be there...
- You are free to contribute on this repo adding pybasses to more things researching on it and this is it for now peace out...

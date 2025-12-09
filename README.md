# React-Next-Scanner 
Safe CLI scanner for **CVE-2025-55182** and **CVE-2025-66478**

This tool provides a lightweight, non-exploitative vulnerability scanner focused on modern JavaScript stacks, specifically:
- API services affected by **CVE-2025-55182**
- Next.js applications affected by **CVE-2025-66478**

It works on:
✅ Windows  
✅ Linux  
✅ macOS  

---

## ✨ Features
- Cross-platform Python CLI scanner  
- Heuristic and safe probing (no exploitation)  
- Detects public fingerprint leaks  
- Optional insecure mode for testing self-signed targets  
- Fast scanning with minimal dependencies  

---

## 📦 Files

| File | Description |
|------|-------------|
| `react_nextjs_scanner.py` | Main scanner script (Python 3.x, cross-platform) |
| `requirements.txt` | Dependencies for installation |
| `README.md` | Project documentation |

---

## 🛠️ Installation

1. **Create a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage Examples

  python3 react_nextjs_scanner.py http://127.0.0.1:3000
  python3 react_nextjs_scanner.py -f targets.txt --insecure

## 🐚 Exploitation Shell (Lab)

For educational purposes and lab testing, use `react_nextjs_shell.py` to demonstrate RCE (Remote Code Execution) if a vulnerable endpoint is detected.

> **Note**: This tool first performs a scan (using the scanner logic) and if a specific lab-only RCE vulnerability is confirmed, it opens an interactive shell.

Usage:
```bash
python3 react_nextjs_shell.py http://127.0.0.1:8080
# Or skip the scan phase:
python3 react_nextjs_shell.py http://127.0.0.1:8080 --skip-scan
```

### Interactive Shell Commands
Once the shell is open (`Shell>`), you can run system commands like:
- `id`
- `whoami`
- `ls -la`
- `cat /etc/passwd`

---

## 🏗️ Testing with Docker

A `docker-compose.yml` file is provided to easily set up a local vulnerable lab environment.

1. **Start the environment:**
   ```bash
   docker-compose up --build -d
   ```
   This will start:
   - **Frontend**: http://localhost:3000
   - **API Backend**: http://localhost:8080

2. **Run the scanner/shell:**
   ```bash
   # Target the local backend
   python3 react_nextjs_shell.py http://localhost:8080
   ```

3. **Stop the environment:**
   ```bash
   docker-compose down
   ```

---

## 👨‍💻 Author

**FurkanKAYAPINAR**

- **GitHub**: [github.com/FurkanKAYAPINAR](https://github.com/FurkanKAYAPINAR)
- **LinkedIn**: [linkedin.com/in/FurkanKAYAPINAR](https://linkedin.com/in/FurkanKAYAPINAR)

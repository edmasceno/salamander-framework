# 🦎 Salamander Framework (V1)

**Salamander** is a fast, automated batch triage and malware pre-filtering engine written in Python. Engineered as the frontline perimeter scanner of **Project Chimera** (alongside *Black Ant* and *Crow*), Salamander sweeps target directories at scale, uncovers file masquerading via Magic Byte inspection, safely inspects nested archives in ephemeral environments, and flags malicious artifacts using custom YARA signatures before handing them over for deep reverse engineering.

---

## ⚙️ Core Capabilities (v1)

1. **Magic Byte Masquerading Detection:**
   Instead of trusting file extensions, Salamander inspects raw hexadecimal file headers (`MZ` for Windows PE, `PK\x03\x04` for ZIP/JAR, `%PDF`, `\x7fELF` for Linux binaries) and cross-references them against the visible extension to instantly catch disguised executables and hidden archives.
2. **Ephemeral Archive Inspection & Dropper Hunting:**
   Automatically unpacks `.zip` and `.jar` packages into isolated, self-destructing temporary directories (`tempfile.TemporaryDirectory`) to hunt for embedded scripts (`.bat`, `.ps1`, `.vbs`, `.js`, `.wsf`, `.cmd`) and nested binary payloads without contaminating the host filesystem.
3. **O(1) Memory Chunked Hashing:**
   Computes cryptographic checksums (`MD5` and `SHA-256`) using 4096-byte buffered chunks, ensuring multi-gigabyte disk images or large installers can be hashed without memory exhaustion.
4. **Integrated YARA Pattern Engine:**
   Dynamically compiles all `.yar` and `.yara` rules inside the `rules/` directory to perform high-speed signature and behavioral matching across both standalone files and unpacked archive contents.
5. **Structured JSON Telemetry:**
   Exports a clean, UTF-8 encoded forensic triage report (`salamandra_report.json`) detailing scan metadata, total files analyzed, ignored clean files, and flagged anomalies with their corresponding `SHA-256` hashes.

---

## 🎯 Active Detection Logic (`rules/`)

Salamander includes boolean-logic YARA rules designed to minimize SOC alert fatigue by requiring behavioral context rather than triggering on isolated strings:

* **`Java_Suspicious_Behavior` (`High`):** Detects malicious `.jar` droppers and trojans by correlating system command execution (`ProcessBuilder`, `Runtime`, `cmd.exe`, `powershell`, `/bin/sh`) with at least one secondary malicious indicator: network communication (`URL`, `openStream`, `HttpURLConnection`), hidden disk staging (`FileOutputStream`, `java.io.tmpdir`), or anti-forensic timestomping (`setLastModifiedTime`)[: ].

---

## 📂 Project Structure

```text
salamander-framework/
├── rules/
│   └── Java_Suspicious_Behavior.yar  # Behavioral YARA rule for Java droppers
├── .gitignore
├── README.md
└── analyzer.py                       # Core batch scanner & triage CLI
```

---

## 💻 Getting Started

### Prerequisites
- **Python 3.8+**
- **`yara-python`** library:

```bash
pip install yara-python
```

### Execution

1. Place your `.yar` or `.yara` detection rules inside the `rules/` directory.
2. Run the analyzer pointing to the target directory you want to sweep:

```bash
python analyzer.py -t path/to/suspicious_directory/
```

3. Monitor the real-time CLI triage output:

```text
[*] Compilando 1 regra(s) YARA...
[*] Salamandra ativada. Escaneando: samples/
[!] ALERTA: samples/fatura.pdf - Camuflagem Detectada (Extensão .pdf falsa).
[!] ALERTA: samples/mod.jar -> Payload.class - YARA Match: Java_Suspicious_Behavior

[v] Relatório gerado: salamandra_report.json
```

4. Review the generated **`salamandra_report.json`** for downstream SIEM ingestion or pass the flagged hashes/files directly into **Black Ant** for deep static dissection.

---
*Part of **Project Chimera** — Created for the Detection Engineering & DFIR community.*

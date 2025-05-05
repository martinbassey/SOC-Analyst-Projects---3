# SOC Analyst Project Report 3: Malicious Attachment Analysis

**Date:** 2025-05-03  
**Analyst:** Martin Bassey

---

## Objective

Analyze a potentially malicious email attachment (PDF) to detect embedded malware, assess risk, and extract indicators of compromise (IOCs) using static and dynamic techniques.

---

## Tools Used

- **Hybrid Analysis** – Behavioral sandbox analysis  
- **oledump.py** – OLE/macro inspection (for Office files)  
- **eioc.py** – Email IOC extraction  
- **pdfid.py** – PDF keyword analysis  
- **VirusTotal** – Reputation check  
- **PDFcrowd.com** – Online PDF structure inspection

---

##  Executive Summary

A suspicious PDF attachment (`0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74`) was analyzed. Key findings:

- Contains `/OpenAction` (can trigger actions on open)
- VirusTotal detection rate: 8/63 engines  
- Contact with suspicious IP `209.85.208.181`, later identified as a Google mail server  
- No macros or embedded JavaScript detected, but analysis warranted due to phishing context

---

## Sample Acquisition

- **Source:** [Phishing_pot](https://github.com/rf-peixoto/phishing_pot)  
- **File Name:** `sample-728.zip`  
- **SHA256:** `0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74`  
- **Acquired On:** 2025-04-11  

**Email Body Screenshot:**  
![Email Screenshot](https://github.com/user-attachments/assets/263496f4-1246-48e4-a10a-16b814f7c3ba)

---

## Analysis Workflow

### 1. Email & PDF Static Analysis (Linux Terminal)

- **Step 1:** Used `eioc.py` to extract IOCs from email.
- **Step 2:** Used `pdfid.py` to analyze PDF structure.

#### pdfid.py Results

| Indicator        | Count |
|------------------|-------|
| `/JavaScript`    | 0     |
| `/OpenAction`    | 1     |
| `/Launch`        | 0     |
| `/EmbeddedFile`  | 0     |

Screenshots:  
- ![eioc.py Screenshot 1](https://github.com/user-attachments/assets/88f99b09-e19c-4bba-b814-1c96bf592015)  
- ![eioc.py Screenshot 2](https://github.com/user-attachments/assets/a6a03d08-2217-441c-b6d7-686cf74a58f0)

> `/OpenAction` is often used to trigger malicious behavior and requires deeper analysis even without `/JavaScript`.

---

### 2. Dynamic Sandbox Analysis

- **Tool:** [Hybrid Analysis](https://www.hybrid-analysis.com/)
- **Environment:** Windows 10 Sandbox
- **File Submitted:** `sample-728.zip`

Screenshot:  
![Hybrid Analysis Screenshot](https://github.com/user-attachments/assets/d6cca1e3-8446-440c-9aeb-d1b3f70b700d)

---

### 3. VirusTotal Reputation Check

- **Hash Searched:** `0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74`

| Security Vendor | Classification                         |
|------------------|----------------------------------------|
| Avast            | PDF:MalwareX-gen [Phish]               |
| AVG              | PDF:MalwareX-gen [Phish]               |
| Google           | Detected (phishing behavior)           |
| Ikarus           | Spammed.PDF.Doc                        |
| QuickHeal        | Cld.pdf.trojan.1740245139              |
| Skyhigh SWG      | BehavesLike.PDF.Generic.db             |
| Fortinet         | PDF/Minephish.A.gen!Camelot            |

Detection Rate: 8/63  

Screenshot:  
![VirusTotal Screenshot](https://github.com/user-attachments/assets/443deaa9-293f-4e26-a41b-511d91f20eb9)

---

### 4. PDF Structure Analysis (PDFcrowd)

- **Tool:** [PDFCrowd.com](https://pdfcrowd.com/)  
- **Findings:** No embedded executables or Office content. Only CID fonts detected.

Screenshot:  
![PDFCrowd Screenshot](https://github.com/user-attachments/assets/4e7a6854-04ee-4aae-b343-f5b9fedc4689)

---

## Indicators of Compromise (IOCs)

### File Hashes

| Type     | Value                                                                 |
|----------|-----------------------------------------------------------------------|
| SHA256   | `0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74`    |

### Network IOCs

| Type       | Value                           | Verdict         |
|------------|----------------------------------|------------------|
| IP Address | `209.85.208.181`                | Benign (Google) |
| Domain     | `mail-lj1-f181.google.com`      | Benign (Google) |

### File IOCs

| File Path                                                | Status     |
|----------------------------------------------------------|------------|
| `29.328%24_Need_to_move_you_have_24_hours-11794.pdf`     | Malicious  |


---

## MITRE ATT&CK Mapping

| Tactic           | Technique ID | Description                        |
|------------------|--------------|------------------------------------|
| Initial Access   | T1566.001    | Spearphishing Attachment           |
| Defense Evasion  | T1027        | Obfuscated Files or Information    |
| Discovery        | T1083        | File and Directory Discovery       |

---

## Recommendations

- To block the malicious file hash and filename patterns in AV/EDR
- To add sample to internal threat intel feeds
- To search mail gateways for similar attachments
- To use this sample in user awareness phishing simulation
- To deploy YARA rules for `/OpenAction` and suspicious PDF behavior

---

## Supporting Links

- [Hybrid Analysis Report](https://www.hybrid-analysis.com/sample/5ab72dfe878fb1c79e1a3921f9cce65b547b8f4d614ff164b9100a04d07e2110)  
- [VirusTotal Report](https://www.virustotal.com/gui/file/0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74/detection)

---

## References

- [Phishing_pot (Email Samples)](https://github.com/rf-peixoto/phishing_pot)  
- [Hybrid Analysis](https://www.hybrid-analysis.com/)  
- [VirusTotal](https://www.virustotal.com/)  
- [Email IOC Extractor (eioc.py)](https://github.com/MalwareCube/Email-IOC-Extractor/blob/main/eioc.py)  
- [PDFCrowd](https://pdfcrowd.com/)

---

## Thank You for Reviewing!

*This project demonstrates the full workflow of malware attachment analysis and the importance of validating threat intelligence to avoid false positives.*

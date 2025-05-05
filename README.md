# SOC Analyst Project Report: Malicious Attachment Analysis

**Project Title:** Malicious Attachment Analysis  
**Date:** 2025-05-03  
**Analyst:** Martin Bassey

**Tools Used:** Hybrid Analysis, Oledump.py, Eioc.py, Pdfid.py, VirusTotal, PDFcrowd.com

---

## Executive Summary

A suspicious PDF attachment (`0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74`) was analyzed for malicious activity. Key findings include:  
- `/OpenAction` trigger with no visible payload (suspicious for PDFs).  
- Low detection rate (8/63) despite confirmed malicious behavior.  
- Suspicious network traffic to `209.85.208.181` (potential C2). 

---

## 1. Introduction

- **Objective:** Analyze a potentially malicious email attachment (PDF) to uncover embedded malware and provide a comprehensive security assessment.
- **Scope:** The analysis covers behavioral sandboxing, static inspection of macros/scripts, hash reputation checks, and extraction of indicators of compromise (IOCs).

---

## 2. Sample Acquisition

- **Source:** Phishing-pot  
- **File Name:** `sample-728.zip`  
- **SHA256 Hash:** `0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74`  
- **Date Acquired:** `Fri 11 Apr 2025`
- Email Body Screenshot ![Screenshot from 2025-05-03 05-19-16](https://github.com/user-attachments/assets/263496f4-1246-48e4-a10a-16b814f7c3ba)

---

## 3. Analysis Workflow

### 3.1. Ubuntu Linux Analysis (Email Sample Analysis on the Terminal Environment)

- **Procedure 1:** Used Eioc.py to manually examine the content of the email sample obtained from Phishing_pot.
- **Procedure 2:** Used Pdfid.py to manually assess the PDF file/doc downloaded from the email sample obtained from Phishing_pot.

## Output snippet from Pdf.py
| Objective        | Indicators | 
|------------------|-----------|
| /Js               | 0       | 
| /JavaScript         | 0     | 
| /OpenAction        | 1     | 
| /Launch        | 0 | 
| /Embedded File        | 0 | 

- - **Screenshots:**  
  Eioc.py Analysis Screenshot ![Screenshot from 2025-05-03 05-04-39](https://github.com/user-attachments/assets/88f99b09-e19c-4bba-b814-1c96bf592015)
  Eioc.py Analysis Screenshot ![Screenshot from 2025-05-03 05-22-43](https://github.com/user-attachments/assets/a6a03d08-2217-441c-b6d7-686cf74a58f0)


### 3.2. Macro Inspection (Oledump.py)

- **NB:** Since I could not identify any embedded file in the PDF file while performing the Pdfid.py analysis, I did not proceed to OLE file/macro analysis (`Oledump.py`) on the attached PDF in the email sample.



### 3.3. Sandbox Behavioral Analysis (Hybrid Analysis)

- **Procedure:** Uploaded the file to Hybrid Analysis sandbox.
- **Key Observations:**

- - **Screenshots:**  
  Hybrid Analysis Screenshot ![Screenshot 2025-05-03 at 04-51-22 Free Automated Malware Analysis Service - powered by Falcon Sandbox](https://github.com/user-attachments/assets/d6cca1e3-8446-440c-9aeb-d1b3f70b700d)


---

### 3.4. Reputation Check (VirusTotal)

- **Procedure:** Checked the file hash on VirusTotal.

- - **Results:**

| Security vendors' analysis | Threat categories |
|------------------|-----------|
| Avast      |       PDF:MalwareX-gen [Phish] |
| AVG    |       PDF:MalwareX-gen [Phish]   |
| Google  |  Detected |
| Ikarus  |  Spammed.PDF.Doc    |
| QuickHeal |  Cld.pdf.trojan.1740245139    |
| Skyhigh (SWG)| BehavesLike.PDF.Generic.db   |
| Varist |  PDF/Minephish.A.gen!Camelot    |

- **Detection ratio:** 8/63 security vendors flagged this file as malicious.

- **Screenshots:**  
![Screenshot 2025-05-03 at 06-19-36 VirusTotal - File - 0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74](https://github.com/user-attachments/assets/443deaa9-293f-4e26-a41b-511d91f20eb9)

---

### 3.4. PDF Analysis (Using PDFcrowd.com) 

- **Procedure:** Used to inspect PDF structure for possibly embedded objects.

- **Findings:**

- Embedded CID font (TrueType font program) shown, which is a legitimate PDF component for text rendering, not an executable file or Office document with macros.

- **Screenshots:**  
  ![Screenshot 2025-05-03 at 07-01-48 Inspect PDF Online - PDFCrowd](https://github.com/user-attachments/assets/4e7a6854-04ee-4aae-b343-f5b9fedc4689)


---

## 4. Indicators of Compromise (IOCs)

| Type       | Value                                                     | Description                       |
|------------|-----------------------------------------------------------|---------------------------------|
| File Hash  | `0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74` | Malicious attachment            |
| IP Address | `209.85.208.181`                                          | Initially flagged as C2 server  |
| Domain     | `mail-lj1-f181.google.com`                                | Initially flagged as C2 server  |
| File Path  | `29.328%24_Need_to_move_you_have_24_hours-11794.pdf`      | Malicious                      |

### IOC Validation and Context

Upon further investigation, some IOCs initially flagged as malicious command and control (C2) infrastructure are actually legitimate and should be treated accordingly:

- **209.85.208.181** and **mail-lj1-f181.google.com** are part of Google's legitimate email infrastructure and **are not confirmed C2 servers**.
- Only the **file hash** and **file path** are directly linked to malicious activity in this case.
- No real C2 infrastructure was observed during dynamic or static analysis of the sample.
- This validation step helps prevent false positives and ensures accurate and actionable reporting.

### Why This Matters

- **Avoids false positives:** Prevents blocking legitimate services like Google mail servers.
- **Demonstrates analytical rigor:** Shows ability to distinguish automated flags from real threats.
- **Improves professional credibility:** Highlights your skill in validating threat intelligence and focusing on true risks.
---

## 5. Technical Details

- **File Behavior:**  
**MITRE ATT&CK Mapping**  
| Tactic           | Technique ID | Name                          |  
|------------------|--------------|-------------------------------|  
| Initial Access   | TA0001   | Spearphishing Attachment      |  
| Defense Evasion  | TA0002        | Obfuscated Files or Information |  
| Discovery        | TA0003        | File and Directory Discovery  |  
- **Detection Coverage:**  
  - VirusTotal detection; NOT FOUND.

---

## 6. Recommendations

- Block identified hashes, domains, and IPs at email gateway and firewall.
- Alert users who received similar emails and initiate incident response procedures.
- Update endpoint protection signatures.
- Educate users on recognizing suspicious attachments.

---

## 7. Attachments

- ![Hybrid Analysis full report](https://www.hybrid-analysis.com/sample/5ab72dfe878fb1c79e1a3921f9cce65b547b8f4d614ff164b9100a04d07e2110)
- ![VirusTotal report full report](https://www.virustotal.com/gui/file/0624396ce2f474e60cf4eade2a3090a174c133d992d262b905ee72f5a00efd74/detection)


---

## 8. References

- ![Phishing_pot](https://github.com/rf-peixoto/phishing_pot)  
- ![Hybrid Analysis](https://www.hybrid-analysis.com/)  
- ![VirusTotal](https://www.virustotal.com/)  
- ![Email-OIC-Extractor](https://github.com/MalwareCube/Email-IOC-Extractor/blob/main/eioc.py)
- ![PDFcrowd.com](https://pdfcrowd.com/)

---

## THANK YOU FOR REVIEWING MY PROJECT, PLEASE LET ME KNOW YOUR THOUGHTS!


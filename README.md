# SOC-Analyst-Projects---3
Malicious Attachment Analysis - Project 3
# SOC Analyst Project Report: Malicious Attachment Analysis

**Project Title:** Malicious Attachment Analysis  
**Date:** 2025-04-29  
**Analyst:** [Your Name]  
**Tools Used:** Hybrid Analysis, Oledump.py, VirusTotal, PDFcrowd.com

---

## Executive Summary

This report documents the analysis of a suspicious email attachment, suspected of containing malware. The objective was to identify any hidden threats, understand the attack vector, and provide actionable intelligence for mitigation. The attachment was analyzed using industry-standard tools and methodologies, with findings summarized for both technical and non-technical stakeholders.

---

## 1. Introduction

- **Objective:** Analyze a potentially malicious email attachment (PDF, .docm, or .zip) to uncover embedded malware and provide a comprehensive security assessment.
- **Scope:** The analysis covers behavioral sandboxing, static inspection of macros/scripts, hash reputation checks, and extraction of indicators of compromise (IOCs).

---

## 2. Sample Acquisition

- **Source:** [MalwareBazaar/VirusShare]  
- **File Name:** `[malicious_sample.docm/pdf/zip]`  
- **SHA256 Hash:** `[Insert hash]`  
- **Date Acquired:** `[Insert date]`

---

## 3. Analysis Workflow

### 3.1. Sandbox Behavioral Analysis (Hybrid Analysis)

- **Procedure:** Uploaded the file to Hybrid Analysis sandbox.
- **Key Observations:**

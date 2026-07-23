---
title: "DuckScope"
date: 2026-01-15
categories: ["Project"]
tags: ["digital-forensics", "steganography", "python", "automation", "ctf"]
description: "An automated image-forensics toolkit that combines multiple steganography and file-analysis utilities into one workflow."
pond: false
status: "In Progress"
technologies: ["Python", "Binwalk", "Foremost", "Steghide", "Outguess", "Zsteg"]
repository: "https://github.com/171k/duckscope"
featured: false
---

# DuckScope

DuckScope is an automated image and steganography analysis toolkit designed to reduce repetitive work during digital-forensics investigations and CTF challenges.

## The problem

Investigating a suspicious image often requires running many separate tools and interpreting their outputs individually.

An analyst may need to inspect:

- File metadata
- Magic bytes
- Embedded files
- Appended data
- Least-significant-bit content
- Steghide containers
- Outguess content
- Compressed archives
- Unusual file signatures

Running each utility manually is slow and can cause analysts to overlook evidence.

## What I built

I designed DuckScope as a single analysis workflow that runs multiple forensic and steganography checks against an uploaded image.

The toolkit integrates utilities such as:

- Binwalk
- Foremost
- Steghide
- Outguess
- Zsteg
- File-signature inspection
- LSB-related analysis

The intended workflow includes:

1. Validating the submitted file
2. Identifying its actual file type
3. Inspecting headers and signatures
4. Searching for embedded or appended data
5. Running relevant steganography utilities
6. Extracting recoverable files
7. Collecting and normalizing tool output
8. Producing an investigation summary
9. Assigning a suspiciousness score

The suspiciousness score is intended to help users prioritize files that contain unusual signatures, embedded content, extraction results, or other indicators.

My contribution includes the tool concept, analysis workflow, integration planning, scoring design, and forensic-report structure.

## What I learned

This project taught me that forensic automation is not only about executing tools.

The difficult part is interpreting and combining results from tools that produce different output formats and levels of reliability.

I learned about:

- File signatures and magic bytes
- Embedded-file extraction
- Steganography techniques
- Handling subprocess output in Python
- Designing repeatable forensic workflows
- Separating confirmed evidence from suspicious indicators
- Avoiding misleading automated conclusions

A major challenge is preventing the suspiciousness score from presenting false positives as confirmed malicious activity.

Future improvements include structured JSON reports, a web interface, file hashes, metadata extraction, safer sandboxing, report exports, and clearer explanations for each finding.

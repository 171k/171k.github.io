---
title: "UiTM Cyber Range"
date: 2026-07-01
categories: ["Project"]
tags: ["cybersecurity", "cyber-range", "ctf", "docker", "kubernetes", "devops"]
description: "A web-based cyber range for practical red-team, blue-team, CTF, and threat-intelligence training."
pond: false
status: "In Progress"
technologies: ["CTFd", "Docker", "Kubernetes", "Linux", "Grafana", "Harbor"]
demo: "https://awan.uitm.edu.my/ctf"
featured: true
gallery: "/assets/images/projects/uitmcyberrange"
gallery_title: "UiTM Cyber Range gallery"
gallery_alt: "UiTM Cyber Range platform and infrastructure screenshot"
---

# UiTM Cyber Range

UiTM Cyber Range is my final-year project focused on providing students with a practical environment for learning cybersecurity through hands-on exercises.

## The problem

Cybersecurity students often learn concepts through lectures and static lab instructions but have limited access to realistic, repeatable environments where they can practise offensive and defensive security skills.

Existing public platforms may not match university syllabuses, local training requirements, or the infrastructure available within the institution.

## What I built

I designed a web-based cyber range that can host multiple forms of cybersecurity training within one platform.

The planned training modules include:

- Jeopardy-style CTF challenges
- Red-team and blue-team exercises
- Attack-and-Defense scenarios
- Threat-intelligence simulations
- SIEM monitoring and log-analysis activities
- AI-assisted hints for students

The platform uses containerized environments so that challenges can be deployed separately and reset without affecting the main system.

My work includes:

- Designing the overall system architecture
- Planning user roles and training workflows
- Configuring containerized challenge environments
- Exploring Kubernetes-based deployment
- Integrating monitoring for platform and container health
- Designing the challenge-management and participant experience
- Preparing the platform for university cybersecurity training

## What I learned

This project helped me understand that building a cyber range involves more than creating cybersecurity challenges.

I learned about:

- Container isolation and resource management
- Kubernetes deployment concepts
- Monitoring infrastructure with Grafana
- Designing secure multi-user environments
- Balancing usability with security
- Planning systems for students, instructors, administrators, red teams, and blue teams

One of the main challenges is ensuring that training environments remain isolated while still being easy for instructors to deploy and manage.

Future improvements include automated challenge provisioning, stronger resource limits, better instructor analytics, and expanded defensive-security scenarios.

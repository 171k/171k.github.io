---
title: "OPUCC26 CTF Platform and Infrastructure"
date: 2026-07-11
categories: ["Project"]
tags: ["ctf", "ctfd", "docker", "linux", "infrastructure", "cybersecurity"]
description: "A customized CTF platform operated for a 24-hour university competition involving 48 teams and 46 challenges."
pond: true
status: "Completed"
technologies: ["CTFd", "Docker Compose", "Linux", "Nginx", "MySQL", "Redis"]
demo: "https://awan.uitm.edu.my/ctf/"
featured: true
---

# OPUCC26 CTF Platform and Infrastructure

OPUCC26 was a 24-hour internal cybersecurity competition organized for UiTM students across Malaysia.

I served as the lead challenge creator and was involved in monitoring and supporting the competition infrastructure.

## The problem

A live CTF competition requires a platform that can reliably handle participant accounts, challenge submissions, scoring, file downloads, containerized services, and real-time support.

The system also needed to remain stable throughout a 24-hour event while supporting 48 participating teams and 46 cybersecurity challenges.

## What I built

I contributed to the development, customization, and operation of a CTFd-based competition platform.

The platform included:

- User registration and authentication
- Challenge categories and scoring
- Live scoreboards
- Challenge files and service instances
- Achievement and ranking systems
- Participant announcements
- Discord integrations
- Custom platform styling and navigation

I personally authored 17 of the 46 challenges used during the event.

My challenges covered formats such as:

- Digital forensics
- Reverse engineering
- Miscellaneous security challenges
- Network-traffic analysis
- Discord bot interactions
- Roblox and RPG Maker environments
- Interactive security puzzles

During the competition, I also:

- Monitored challenge availability
- Responded to participant sanity-check tickets
- Investigated challenge deployment issues
- Supported infrastructure troubleshooting
- Coordinated fixes with the infrastructure team
- Verified whether reported challenge issues were technical problems or intended behaviour

## What I learned

Operating a live competition taught me how different production systems are from development environments.

I gained experience in:

- Troubleshooting under time pressure
- Managing Docker-based services
- Working with CTFd, Nginx, Redis, and MySQL
- Investigating participant reports
- Distinguishing platform issues from challenge-design issues
- Coordinating technical work during a live event
- Designing challenges with clear and fair solution paths

The event also showed me the importance of monitoring, backups, challenge testing, and clear communication between challenge creators and infrastructure maintainers.

Future improvements would include more automated health checks, standardized challenge deployment templates, stronger pre-event load testing, and improved internal documentation.

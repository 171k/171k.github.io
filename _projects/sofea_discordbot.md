---
title: "Sofea Discord Security Challenge Bot"
date: 2026-07-07
categories: ["Project"]
tags: ["discord", "security", "prompt-injection", "ctf", "bot-development"]
description: "A stateful Discord bot used to deliver an interactive staged security challenge through commands, reports, and controlled conversation flows."
pond: false
status: "Completed"
technologies: ["Node.js", "Discord.js", "PM2", "Discord API", "Linux"]
featured: false
gallery: "/assets/images/projects/sofeadiscordbot"
gallery_title: "Sofea bot gallery"
gallery_alt: "Sofea Discord security challenge bot screenshot"
---

# Sofea Discord Security Challenge Bot

Sofea is a custom Discord bot created for an interactive cybersecurity challenge.

Instead of presenting participants with a traditional downloadable file or web page, the challenge takes place through conversations, commands, modal submissions, and state changes inside Discord.

## The problem

Many CTF challenges can be solved by downloading a file and sending it directly to an automated tool or AI agent.

I wanted to design a challenge that required participants to interact with a live system, understand its behaviour, experiment with different inputs, and track how the bot responded over multiple stages.

The challenge also needed to operate safely within selected Discord channels without disrupting the rest of the server.

## What I built

I developed a Discord bot with stateful interaction and administrative controls.

The bot included commands such as:

- `/help`
- `/about`
- `/report`
- `/reset-sofea`

The `/report` command opened a private modal where participants could submit information to the bot.

The bot tracked user progress and changed its behaviour depending on the participant's current state.

Additional bot features included:

- Per-user challenge state
- Controlled response stages
- Private modal submissions
- Staff-only reset functionality
- Channel and category restrictions
- Submission logging
- Error handling
- Process management using PM2
- Administrative monitoring

The challenge involved staged injection-style interactions where participants had to understand how the bot processed instructions and how different inputs influenced its behaviour.

I also implemented logs that recorded submitted reports, user identifiers, challenge states, and result statuses to help monitor the challenge during the event.

## What I learned

This project gave me experience building a live interactive security challenge rather than a static challenge file.

I learned about:

- Discord slash commands
- Modal interactions
- Discord permissions
- Per-user state management
- Bot event handling
- Logging and operational monitoring
- Restricting functionality by server category or channel
- Managing Node.js processes using PM2
- Designing multi-stage challenge logic

One of the main difficulties was preventing participants from skipping intended stages while ensuring that legitimate solutions were accepted consistently.

I also had to consider how Discord formatting, message length, permissions, and user concurrency affected the challenge.

Future improvements include persistent database storage, improved rate limiting, automated health checks, a staff dashboard, and more detailed analytics for participant attempts.

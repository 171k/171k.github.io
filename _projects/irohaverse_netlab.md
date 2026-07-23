---
title: "IrohaVerse Network Forensics Lab"
date: 2026-07-07
categories: ["Project"]
tags: ["network-forensics", "wireshark", "pcap", "web-security", "ctf"]
description: "A simulated social networking environment designed for investigating suspicious activity through captured network traffic."
pond: true
status: "Completed"
technologies: ["Wireshark", "PCAP", "HTTP", "HTML", "CSS", "JavaScript"]
demo: "http://129.212.225.109:8080/"
featured: false
gallery: "/assets/images/projects/irohaverse"
gallery_title: "IrohaVerse interface gallery"
gallery_alt: "IrohaVerse network-forensics lab interface screenshot"
---

# IrohaVerse Network Forensics Lab

IrohaVerse is a simulated social networking website and network-forensics challenge designed to teach participants how to investigate web activity through packet captures.

The project combines a realistic website environment with generated network traffic that can be examined using Wireshark.

## The problem

Students learning network forensics may understand protocols theoretically but have limited experience investigating a realistic sequence of user activity.

Simple packet-capture exercises often reveal the answer immediately and do not require participants to understand the context surrounding the traffic.

I wanted to create a scenario where participants had to explore a believable website, understand its features, inspect captured communication, and reconstruct what occurred.

## What I built

I created a fictional social networking platform called IrohaVerse.

The website included features such as:

- User accounts
- Profile pages
- Public posts
- Comments
- Friend connections
- Private chat messages
- Administrative authentication
- Simulated user activity

I then generated a packet capture containing traffic associated with the website.

Participants were required to use Wireshark to:

1. Identify the relevant network conversations
2. Filter HTTP traffic
3. Examine requests and responses
4. Reconstruct user activity
5. Locate authentication-related information
6. Determine which account or action was important
7. Recover the challenge flag from the investigation

I designed both the website content and the investigation path so that the packet capture contained enough surrounding traffic to require analysis rather than a simple keyword search.

## What I learned

This project helped me understand how application design affects the network evidence available to investigators.

I learned about:

- HTTP request and response structures
- Wireshark display filters
- Packet-capture generation
- Authentication traffic
- Reconstructing user actions from network evidence
- Designing realistic forensic scenarios
- Balancing challenge difficulty with investigation clarity

One challenge was ensuring that the important evidence could be discovered without making the answer immediately visible.

I also learned that network-forensics challenges need a clear timeline and consistent application behaviour so that participants can distinguish useful evidence from background traffic.

Future improvements include adding HTTPS decryption material, DNS traffic, uploaded files, session analysis, and a more detailed incident timeline.

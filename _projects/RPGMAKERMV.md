---
title: "RPG Maker MV CTF Challenge"
date: 2026-07-11
categories: ["Project"]
tags: ["rpg-maker", "ctf", "javascript", "game-development", "security-challenge"]
description: "An interactive RPG-style cybersecurity challenge where participants explore a game world, investigate clues, and manipulate in-game systems to uncover a hidden flag."
pond: true
status: "Completed"
technologies: ["RPG Maker MV", "JavaScript", "HTML5", "Node.js", "Game Event Scripting"]
featured: false
gallery: "/assets/images/projects/rpgmakermv"
gallery_title: "RPG Maker MV challenge gallery"
gallery_alt: "RPG Maker MV cybersecurity challenge development screenshot"
---

# RPG Maker MV Interactive Security Challenge

This project is an interactive cybersecurity challenge built using RPG Maker MV.

Instead of giving participants a traditional file, terminal, or web application, the challenge places them inside a small role-playing game where they must explore the environment, interact with characters, understand the game logic, and discover how to trigger the hidden ending.

## The problem

Many CTF challenges follow predictable formats and can be solved by immediately inspecting a file with automated tools.

I wanted to create a challenge that required participants to understand a game environment, observe character dialogue, investigate in-game conditions, and determine how the game stores or validates player progress.

The challenge also needed to remain approachable for beginners while still rewarding technical investigation.

## What I built

I created a small RPG Maker MV game containing:

- A custom game map
- Interactive non-player characters
- Dialogue-based clues
- A shop and item-purchasing system
- Switches and variables controlling game progress
- Conditional events
- Locked areas
- Hidden challenge logic
- A final event that reveals the flag

The main puzzle required the player to obtain an item that was intentionally too expensive to purchase through normal gameplay.

Participants had to investigate how the game represented player gold, inventory, switches, and variables before determining how to satisfy the event condition.

The challenge flow included:

1. Exploring the game world
2. Speaking with non-player characters
3. Identifying the required item
4. Discovering that the normal purchase price was unreachable
5. Inspecting or manipulating the local game state
6. Returning to the relevant character
7. Triggering the hidden event
8. Recovering the final flag

I used RPG Maker MV event commands to control:

- Item checks
- Gold requirements
- Dialogue branches
- Character movement
- Switch activation
- Variable comparisons
- Cutscenes
- Completion conditions

Because RPG Maker MV games are built using web technologies, the challenge could also be inspected through its JavaScript files and local save-data structure.

## My contribution

I was responsible for:

- Designing the challenge concept
- Building the game map
- Writing the dialogue and clues
- Creating the shop and item puzzle
- Configuring switches and variables
- Designing the progression logic
- Implementing the final flag event
- Testing intended and unintended solution paths
- Packaging the game for participants
- Balancing the difficulty for a medium-level CTF challenge

## What I learned

This project helped me understand how game engines manage state and progression.

I learned about:

- RPG Maker MV event systems
- Game switches and variables
- Conditional event logic
- Local save-data structures
- Inventory and currency handling
- JavaScript-based game deployment
- Browser-compatible game packaging
- Designing security challenges inside non-traditional platforms

One major challenge was ensuring that the puzzle could not be solved simply by guessing the answer or reading an obvious file.

I also had to prevent unintended shortcuts, such as exposing the flag directly in dialogue files, image metadata, event names, or easily searchable source code.

The project showed me that game-based security challenges can combine technical analysis with environmental storytelling and player exploration.

## Future improvements

Future versions could include:

- Encrypted or obfuscated save data
- Multiple valid solution paths
- More complex event dependencies
- Custom JavaScript plugins
- Anti-tampering checks
- A larger investigation area
- Dynamic NPC behaviour
- Server-side validation for the final flag
- Better mobile browser support
- More detailed player-attempt logging

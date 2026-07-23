---
layout: default
title: 171k | Razlan's duck pond
description: Cybersecurity projects, CTF challenges, forensic tools, and practical field notes by Razlan.
---

<section class="profile-panel" id="title">
    <p class="profile-kicker">Hello from the pond. I'm</p>
    <h1>Razlan <span>/ 171k</span></h1>
    <p class="profile-role">Cybersecurity student building CTF challenges, forensic tools, and interactive security experiences.</p>

    <div class="profile-copy">
        <p>I design security challenges, investigate digital evidence, build practical tooling, and document the mistakes and discoveries along the way. <strong>171k</strong> comes from “itik”, Malay for duck.</p>
    </div>

    <dl class="profile-facts">
        <div><dt>17 challenges</dt><dd>Authored for the OPUCC26 CTF</dd></div>
        <div><dt>48 teams</dt><dd>Supported during a 24-hour competition</dd></div>
        <div><dt>President</dt><dd>UiTM Cyberheroes Club, 2025/2026</dd></div>
    </dl>

    <nav class="profile-actions" aria-label="Primary actions">
        <a class="profile-action-primary" href="/projects/">View projects</a>
        <a href="/search/?q=ctf">Read CTF writeups</a>
        <a href="mailto:razlanbramli@gmail.com">Contact me</a>
    </nav>

    <a class="profile-pond-entry" href="/pond/">
        <span>
            <small>Interactive portfolio</small>
            <strong>Go to Duck Pond</strong>
            <span>Explore projects, writeups, and achievements through the 3D pond.</span>
        </span>
        <b aria-hidden="true">↗</b>
    </a>

    <div class="profile-socials" id="contact">
        <span>Elsewhere</span>
        <a href="https://www.linkedin.com/in/razlan-ramli-99a527186/">LinkedIn ↗</a>
        <a href="https://discord.com/users/871586020381061160">Discord ↗</a>
        <a href="mailto:razlanbramli@gmail.com">Email ↗</a>
    </div>
</section>

{% assign featured_projects = site.projects | where: "featured", true | sort: "date" | reverse %}
{% assign featured_achievements = site.achievements | where: "featured", true | sort: "date" | reverse %}
{% assign featured_certifications = site.certifications | where: "featured", true | sort: "date" | reverse %}
{% assign featured_posts = site.quacks | where: "featured", true | sort: "date" | reverse %}
{% assign featured_items = featured_projects | concat: featured_achievements | concat: featured_certifications | concat: featured_posts %}

<section class="recent-section" id="featured">
    <div class="section-heading">
        <div>
            <p class="section-kicker">Pinned highlights</p>
            <h2>Featured work</h2>
        </div>
        <span class="section-count">{{ featured_items | size }} pinned</span>
    </div>

    <div class="post-list">
        {% for item in featured_items limit:6 %}
        <article class="post-row">
            <a href="{{ item.url }}" class="post-row-link" aria-label="Read {{ item.title }}"></a>
            <div class="post-row-meta">
                <time datetime="{{ item.date | date_to_xmlschema }}">{{ item.date | date: "%d %b %Y" }}</time>
                {% case item.collection %}
                    {% when "projects" %}<span>Project</span>
                    {% when "certifications" %}<span>Certification</span>
                    {% when "achievements" %}<span>Achievement</span>
                    {% else %}<span>{{ item.categories | first | default: "Field note" }}</span>
                {% endcase %}
            </div>
            <div class="post-row-body">
                <h3>{{ item.title }}</h3>
                <p>{{ item.description | default: item.summary | default: item.excerpt | strip_html | truncate: 145 }}</p>
                {% if item.collection == "projects" %}
                    {% if item.technologies %}
                    <div class="post-row-tech" aria-label="Technologies used">
                        {% for technology in item.technologies limit:4 %}<span>{{ technology }}</span>{% endfor %}
                    </div>
                    {% endif %}
                {% endif %}
            </div>
            <span class="post-row-arrow" aria-hidden="true">↗</span>
        </article>
        {% else %}
        <div class="portfolio-empty"><p>Mark an entry with <code>featured: true</code> to pin it here.</p></div>
        {% endfor %}
    </div>
</section>

<section class="collection-grid" aria-label="Explore the site">
    <div class="collection-card">
        <span class="collection-index">01</span>
        <h2>CTF writeups</h2>
        <p>Challenge notes grouped by event, ready from the sidebar.</p>
    </div>
    <div class="collection-card">
        <span class="collection-index">02</span>
        <h2>Tools I use</h2>
        <p>Practical references for Wireshark, Apktool, and the rest of the toolkit.</p>
    </div>
    <div class="collection-card">
        <span class="collection-index">03</span>
        <h2>Books &amp; sheets</h2>
        <p>Longer notes, cookbooks, and reusable learning material.</p>
    </div>
</section>

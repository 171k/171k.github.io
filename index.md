---
layout: default
title: welcome, duckies!
---

<h1 id="title"> Welcome To My Territory 🦆</h1>
<p>Feel free to read everything I put here! I am a beginner so correct me if I am wrong!</p>

<div class="content-box" id="about">
    <h2>🦆 Who Quacked This?</h2>
    <p>Qwack! I'm <strong>Razlan</strong>, a beginner cybersecurity enthusiast trying to dip my legs into the world of cybersecurity. I am still learning and trying my best to be better so please be nice to me hehe. Why 171k? because it stands for "itik" and I love ducks :3 </p>

    <p>🎯 <strong>Current Focus:</strong> Digital Forensics and Mobile Hacking</p>
    <p>🏆 <strong>CTF Teams:</strong> Member of UiTM Cyberheroes Club Team</p>
    <p> For Writeups, I only do Forensics and Reverse Engineering Writeup unless requested to do something else!</p>
</div>

<hr class="section-divider" />

<!-- Featured Posts Section -->
<div id="featured-posts-section">
    <h1> Featured Posts </h1>
    <div class="featured-posts">
        {% assign latest_posts = site.posts | sort: 'date' | reverse %}
        {% for post in latest_posts limit:3 %}
        <article class="featured-post">
            <div class="post-meta">{{ post.date | date: "%b %d, %Y" }}</div>
            <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
            <p>{{ post.excerpt | strip_html | truncate: 160 }}</p>
            <a class="read-more" href="{{ post.url }}">Read more →</a>
        </article>
        {% endfor %}
    </div>
</div>

<hr class="section-divider" />

<div class="content-box" id="contact">
    <h2>📬 Throw me a crumbs 🥖</h2>
    <div class="contact-content">
        <p>Want to connect or collaborate? Feel free to reach out!</p>
        <div class="contact-links">
            <a href="https://www.linkedin.com/in/razlan-ramli-99a527186/" class="contact-link">💼 LinkedIn</a>
            <a href="https://discord.com/users/871586020381061160" class="contact-link">🎮 discord</a>
            <a href="mailto:your-lanbuatkeje@gmail.com" class="contact-link">📧 Email</a>
        </div>
        <p class="contact-note">Always happy to discuss cybersecurity, CTFs, or share learning resources!</p>
    </div>
</div>

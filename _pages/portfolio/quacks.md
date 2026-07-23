---
layout: default
title: Quacks
description: Blog-style field notes, experiences, reflections, and cybersecurity stories by Razlan.
permalink: /quacks/
---

<section class="portfolio-page">
    <p class="section-kicker">From the notebook</p>
    <h1>Quacks</h1>
    <p class="portfolio-intro">Blog-style notes, event stories, reflections, and things I wanted to write down.</p>

    {% assign quacks_sorted = site.quacks | sort: 'date' | reverse %}
    <div class="post-list">
        {% for quack in quacks_sorted %}
        <article class="post-row">
            <a href="{{ quack.url }}" class="post-row-link" aria-label="Read {{ quack.title }}"></a>
            <div class="post-row-meta">
                <time datetime="{{ quack.date | date_to_xmlschema }}">{{ quack.date | date: "%d %b %Y" }}</time>
                <span>{{ quack.categories | first | default: "Quack" }}</span>
            </div>
            <div class="post-row-body">
                <h3>{{ quack.title }}</h3>
                <p>{{ quack.description | default: quack.excerpt | strip_html | truncate: 145 }}</p>
            </div>
            <span class="post-row-arrow" aria-hidden="true">↗</span>
        </article>
        {% else %}
        <div class="portfolio-empty"><p>Your quacks will appear here.</p></div>
        {% endfor %}
    </div>
</section>

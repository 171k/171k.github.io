---
layout: default
title: Achievements
description: CTF placements, awards, and cybersecurity milestones achieved by Razlan.
permalink: /achievements/
---

<section class="portfolio-page">
    <p class="section-kicker">Milestones</p>
    <h1>Achievements</h1>
    <p class="portfolio-intro">CTF placements, awards, recognition, and moments worth remembering.</p>

    {% assign entries = site.achievements | sort: 'date' | reverse %}
    {% if entries.size > 0 %}
    <div class="portfolio-list">
        {% for achievement in entries %}
        <article class="portfolio-entry">
            <div class="portfolio-entry-meta">
                <time datetime="{{ achievement.date | date_to_xmlschema }}">{{ achievement.date | date: "%Y" }}</time>
                {% if achievement.organization %}<span>{{ achievement.organization }}</span>{% endif %}
            </div>
            <div>
                <h2><a href="{{ achievement.url }}">{{ achievement.title }}</a></h2>
                <p>{{ achievement.description | default: achievement.summary | default: achievement.excerpt | strip_html | truncate: 180 }}</p>
            </div>
        </article>
        {% endfor %}
    </div>
    {% else %}
    <div class="portfolio-empty"><p>Achievements will appear here when they are added.</p></div>
    {% endif %}
</section>

---
layout: default
title: Projects
description: Cybersecurity projects, labs, scripts, and practical experiments by Razlan.
permalink: /projects/
---

<section class="portfolio-page">
    <p class="section-kicker">Proof of work</p>
    <h1>Projects</h1>
    <p class="portfolio-intro">Things I have built, investigated, automated, or learned by doing.</p>

    {% assign entries = site.projects | sort: 'date' | reverse %}
    {% if entries.size > 0 %}
    <div class="portfolio-list">
        {% for project in entries %}
        <article class="portfolio-entry">
            <div class="portfolio-entry-meta">
                <time datetime="{{ project.date | date_to_xmlschema }}">{{ project.date | date: "%Y" }}</time>
                {% if project.status %}<span>{{ project.status }}</span>{% endif %}
            </div>
            <div>
                <h2><a href="{{ project.url }}">{{ project.title }}</a></h2>
                <p>{{ project.description | default: project.summary | default: project.excerpt | strip_html | truncate: 180 }}</p>
                {% if project.technologies %}<p class="portfolio-tags">{{ project.technologies | join: " / " }}</p>{% endif %}
            </div>
        </article>
        {% endfor %}
    </div>
    {% else %}
    <div class="portfolio-empty"><p>Projects will appear here when they are ready.</p></div>
    {% endif %}
</section>

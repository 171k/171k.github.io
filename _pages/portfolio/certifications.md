---
layout: default
title: Certifications
description: Professional certifications and completed cybersecurity training by Razlan.
permalink: /certifications/
---

<section class="portfolio-page">
    <p class="section-kicker">Validated learning</p>
    <h1>Certifications</h1>
    <p class="portfolio-intro">Certifications, formal training, and courses I have completed.</p>

    {% assign entries = site.certifications | sort: 'date' | reverse %}
    {% if entries.size > 0 %}
    <div class="portfolio-list">
        {% for certification in entries %}
        <article class="portfolio-entry">
            <div class="portfolio-entry-meta">
                <time datetime="{{ certification.date | date_to_xmlschema }}">{{ certification.date | date: "%Y" }}</time>
                {% if certification.issuer %}<span>{{ certification.issuer }}</span>{% endif %}
            </div>
            <div>
                <h2><a href="{{ certification.url }}">{{ certification.title }}</a></h2>
                <p>{{ certification.description | default: certification.summary | default: certification.excerpt | strip_html | truncate: 180 }}</p>
            </div>
        </article>
        {% endfor %}
    </div>
    {% else %}
    <div class="portfolio-empty"><p>Certifications will appear here when they are added.</p></div>
    {% endif %}
</section>

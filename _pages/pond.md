---
layout: default
title: Duck Pond | 171k
description: Explore Razlan's cybersecurity notebook by guiding a white duck through an interactive 3D pond.
permalink: /pond/
body_class: pond-page
pond: true
---

{% include pond-experience.html %}

{% assign pond_posts = site.quacks | concat: site.ctf | concat: site.tools | concat: site.books | concat: site.projects | concat: site.certifications | concat: site.achievements %}
<script id="pond-post-data" type="application/json">
[
{% for post in pond_posts %}
  {
    "id": {{ post.url | jsonify }},
    "title": {{ post.title | jsonify }},
    "url": {{ post.url | jsonify }},
    "description": {{ post.description | default: post.excerpt | strip_html | strip_newlines | jsonify }},
    "date": {{ post.date | date_to_xmlschema | jsonify }},
    "collection": {{ post.collection | jsonify }},
    "categories": {{ post.categories | default: empty | jsonify }},
    "ctfEvent": {{ post.ctf_event | default: "" | jsonify }},
    "ctfCategory": {{ post.ctf_category | default: "" | jsonify }},
    "featured": {{ post.featured | default: false | jsonify }},
    "pond": {{ post.pond | default: false | jsonify }}
  }{% unless forloop.last %},{% endunless %}
{% endfor %}
]
</script>

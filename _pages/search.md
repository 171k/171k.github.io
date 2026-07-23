---
layout: default
title: Search | 171k
description: Search Razlan's cybersecurity notes, CTF writeups, projects, certifications, achievements, tools, and books.
permalink: /search/
---

<section class="search-page">
  <p class="section-kicker">Search the pond</p>
  <h1>Find a note</h1>
  <form class="search-page-form" action="/search/" method="get" role="search">
    <label for="site-search">Search notes, writeups, portfolio entries, tools, and books</label>
    <div>
      <input id="site-search" type="search" name="q" autocomplete="off" placeholder="Try forensics, Wireshark, or phishing">
      <button type="submit">Search</button>
    </div>
  </form>
  <p id="search-summary" class="search-summary" aria-live="polite">Enter a term to search the pond.</p>
  <div id="search-results" class="search-results"></div>
</section>

<script id="search-index" type="application/json">
[
{% assign search_items = site.quacks | concat: site.ctf | concat: site.projects | concat: site.certifications | concat: site.achievements | concat: site.tools | concat: site.books %}
{% for item in search_items %}
  {
    "title": {{ item.title | jsonify }},
    "url": {{ item.url | jsonify }},
    "excerpt": {{ item.description | default: item.content | strip_html | strip_newlines | truncate: 220 | jsonify }},
    "type": {{ item.collection | default: 'post' | jsonify }}
  }{% unless forloop.last %},{% endunless %}
{% endfor %}
]
</script>
<script>
  (function () {
    const form = document.querySelector('.search-page-form');
    const input = document.getElementById('site-search');
    const summary = document.getElementById('search-summary');
    const results = document.getElementById('search-results');
    const index = JSON.parse(document.getElementById('search-index').textContent);

    function render(query) {
      const normalized = query.trim().toLowerCase();
      results.replaceChildren();
      input.value = query;

      if (!normalized) {
        summary.textContent = 'Enter a term to search the pond.';
        return;
      }

      const matches = index.filter(function (item) {
        return (item.title + ' ' + item.excerpt + ' ' + item.type).toLowerCase().includes(normalized);
      }).slice(0, 30);

      summary.textContent = matches.length + (matches.length === 1 ? ' result' : ' results') + ' for “' + query + '”.';

      matches.forEach(function (item) {
        const article = document.createElement('article');
        article.className = 'search-result';
        const link = document.createElement('a');
        link.href = item.url;
        const type = document.createElement('span');
        type.textContent = item.type;
        const title = document.createElement('h2');
        title.textContent = item.title;
        const copy = document.createElement('p');
        copy.textContent = item.excerpt;
        link.append(type, title, copy);
        article.append(link);
        results.append(article);
      });
    }

    form.addEventListener('submit', function (event) {
      event.preventDefault();
      const query = input.value;
      history.replaceState(null, '', '/search/?q=' + encodeURIComponent(query));
      render(query);
    });

    render(new URLSearchParams(location.search).get('q') || '');
  }());
</script>

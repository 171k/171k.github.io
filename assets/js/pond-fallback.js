(function () {
  'use strict';

  const collectionOrder = ['quacks', 'ctf', 'tools', 'books', 'projects', 'certifications', 'achievements'];
  const collectionLabels = {
    quacks: 'Quacks',
    ctf: 'CTF library',
    tools: 'Toolkit',
    books: 'Library',
    projects: 'Projects',
    certifications: 'Certifications',
    achievements: 'Achievements'
  };

  function readPosts() {
    const source = document.getElementById('pond-post-data');
    if (!source) return [];
    try { return JSON.parse(source.textContent); } catch (error) { return []; }
  }

  function displayTitle(post) {
    return post.collection === 'ctf' && post.ctfEvent ? post.ctfEvent + ': ' + post.title : post.title;
  }

  function selectPosts(posts) {
    return collectionOrder.flatMap(function (collection) {
      return posts
        .filter(function (post) { return post.collection === collection && post.pond === true; })
        .sort(function (a, b) { return new Date(b.date).getTime() - new Date(a.date).getTime(); })
        .slice(0, 3);
    });
  }

  window.getPondPosts = function () {
    return selectPosts(readPosts());
  };

  window.showPondFallback = function () {
    const fallback = document.getElementById('pond-fallback');
    const list = document.getElementById('pond-fallback-list');
    const loading = document.getElementById('pond-loading');
    const canvas = document.getElementById('pond-canvas');
    if (!fallback || !list) return;

    list.replaceChildren();
    selectPosts(readPosts()).forEach(function (post) {
      const link = document.createElement('a');
      const type = document.createElement('span');
      const title = document.createElement('strong');
      link.href = post.url;
      type.textContent = collectionLabels[post.collection] || post.collection;
      title.textContent = displayTitle(post);
      link.append(type, title);
      list.append(link);
    });

    if (loading) loading.hidden = true;
    if (canvas) canvas.hidden = true;
    fallback.hidden = false;
  };

  window.setTimeout(function () {
    if (!window.__pondExperienceStarted) window.showPondFallback();
  }, 9000);
}());

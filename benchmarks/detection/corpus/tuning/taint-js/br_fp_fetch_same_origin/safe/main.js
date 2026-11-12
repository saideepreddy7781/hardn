const q = new URLSearchParams(location.search).get('q');
fetch('/api/search?q=' + encodeURIComponent(q)).then(render);

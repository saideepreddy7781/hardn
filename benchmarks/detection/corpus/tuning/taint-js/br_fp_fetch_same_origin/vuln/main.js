const u = new URLSearchParams(location.search).get('u');
fetch(u).then(render);

const q = new URLSearchParams(location.search).get('q');
const el = document.getElementById('a');
el.innerHTML = q;

module.exports = { headers: () => [{ source: '/:p*', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'" }] }] };

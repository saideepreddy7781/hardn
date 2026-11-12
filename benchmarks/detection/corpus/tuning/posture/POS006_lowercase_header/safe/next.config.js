module.exports = { headers: () => [{ source: '/:p*', headers: [{ key: 'content-security-policy', value: "default-src 'self'" }] }] };

jwt.verify(t, k);
const h = jwt.decode(t, { complete: true }).header;

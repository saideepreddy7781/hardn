export function P() {
  const q = new URLSearchParams(location.search).get('q');
  return <div dangerouslySetInnerHTML={{ __html: q }} />;
}

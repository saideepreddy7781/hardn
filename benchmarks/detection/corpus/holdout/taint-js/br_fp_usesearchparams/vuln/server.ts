'use client';
export function P() {
  const searchParams = useSearchParams();
  const q = searchParams.get('q');
  const x = fetch(q);
  return null;
}

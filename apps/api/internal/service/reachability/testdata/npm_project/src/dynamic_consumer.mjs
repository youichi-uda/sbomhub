// Dynamic import consumer: import-level evidence only (no binding tracking).
export async function load() {
  const mod = await import('acme-transitive-parent');
  return mod;
}

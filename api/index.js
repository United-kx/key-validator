export default async function handler(req, res) {
  const { default: app } = await import('../src/server.js');
  return app(req, res);
}

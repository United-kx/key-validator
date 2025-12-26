import type { VercelRequest, VercelResponse } from '@vercel/node';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const { default: app } = await import('../src/server.js');
  return app(req, res);
}

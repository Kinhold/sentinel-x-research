import type { Express } from 'express';
import { createServer } from 'node:http';

export async function request(
  app: Express,
  path: string,
  init: RequestInit = {},
): Promise<{ status: number; json: () => Promise<unknown>; text: () => Promise<string> }> {
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Failed to bind test server');
  const url = `http://127.0.0.1:${address.port}${path}`;
  const response = await fetch(url, init);
  const body = await response.text();
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  return {
    status: response.status,
    json: async () => JSON.parse(body),
    text: async () => body,
  };
}

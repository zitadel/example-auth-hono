import 'dotenv/config';
import { serve } from '@hono/node-server';
import type { Hono } from 'hono';
import { build } from './app.js';

/**
 * Starts the Hono server and begins listening for incoming connections.
 *
 * @returns Promise that resolves when the server starts successfully
 */
async function startServer(): Promise<void> {
  const app: Hono = await build();
  const PORT: number = Number(process.env.PORT) || 3000;

  serve({
    fetch: app.fetch,
    port: PORT,
  });

  console.log(`Stateless server with Hono running on port ${PORT}`);
}

startServer().catch(console.error);

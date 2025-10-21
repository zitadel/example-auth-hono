import { build } from '../src/app.js';
import { Hono } from 'hono';

describe('GET /', () => {
  let app: Hono;

  beforeAll(async () => {
    app = await build();
  });

  it('should return 200 OK and render the home page', async () => {
    const res = await app.request('/');

    expect(res.status).toBe(200);
  });
});

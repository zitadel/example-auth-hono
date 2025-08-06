import { Context, Next } from 'hono';
import Handlebars from 'handlebars';
import { readFileSync } from 'fs';
import { join } from 'path';

// minimal ResponseInit type for HTML responses
type ResponseInit = {
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
};

declare module 'hono' {
  interface Context {
    view<T extends Record<string, unknown> = Record<string, unknown>>(
      name: string,
      data?: T,
      init?: ResponseInit,
    ): Response;
  }
}

export function viewMiddleware() {
  const viewsRoot = join(process.cwd(), 'res');
  const layoutTpl = Handlebars.compile(
    readFileSync(join(viewsRoot, 'main.hbs'), 'utf8'),
  );

  return async (c: Context, next: Next) => {
    c.view = <T extends Record<string, unknown>>(
      name: string,
      data?: T,
      init: ResponseInit = {},
    ): Response => {
      const tplSrc = readFileSync(join(viewsRoot, `${name}.hbs`), 'utf8');
      const tpl = Handlebars.compile(tplSrc);
      const body = tpl(data ?? {});
      return new Response(
        layoutTpl({ body, ...(data as Record<string, unknown>) }),
        {
          ...init,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            ...(init.headers || {}),
          },
        },
      );
    };
    await next();
  };
}

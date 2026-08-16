import cors from 'cors';
import express, {
  type ErrorRequestHandler,
  type RequestHandler,
} from 'express';
import helmet from 'helmet';
import path from 'node:path';

import {
  getPurgeInterval,
  runtimeConfig,
  type RuntimeConfig,
} from './config/runtime-config.js';
import { createAdminController } from './controllers/admin-controller.js';
import { createApiController } from './controllers/api-controller.js';
import { createChunkedApiController } from './controllers/chunked-api-controller.js';
import { createAdminRoutes } from './routes/admin-routes.js';
import { createApiRoutes } from './routes/api-routes.js';
import { createUploadStore } from './services/upload-store.js';

type CreateAppOptions = {
  config?: RuntimeConfig;
  rootDir: string;
};

export function createApp({
  config = runtimeConfig,
  rootDir,
}: CreateAppOptions) {
  const app = express();
  const uploadStore = createUploadStore({ ttlMs: config.ttlMs });
  const adminController = createAdminController({ uploadStore });
  const apiController = createApiController({
    uploadStore,
    ttlMs: config.ttlMs,
    maxJsonBytes: config.maxJsonBytes,
  });
  const chunkedApiController = createChunkedApiController({
    store: uploadStore,
    maxJsonBytes: config.maxJsonBytes,
  });

  app.use('/static', express.static(path.join(rootDir, 'public/static')));
  app.use(
    helmet({
      crossOriginResourcePolicy: false,
      contentSecurityPolicy: false,
    }),
  );
  app.use(
    cors({
      origin:
        config.allowedOrigin === '*'
          ? '*'
          : config.allowedOrigin.split(',').map((origin) => origin.trim()),
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'Range',
        'X-Chunk-IV',
      ],
      exposedHeaders: [
        'Accept-Ranges',
        'Content-Length',
        'Content-Range',
        'X-Chunk-IV',
      ],
    }),
  );

  app.use('/', createAdminRoutes(adminController));
  app.use('/api', createApiRoutes(apiController, chunkedApiController));

  const notFoundHandler: RequestHandler = (_req, res) => {
    res.status(404).json({ error: 'Not found.' });
  };
  app.use(notFoundHandler);

  const errorHandler: ErrorRequestHandler = (_error, _req, res, _next) => {
    res.status(500).json({ error: 'Internal server error.' });
  };
  app.use(errorHandler);

  setInterval(uploadStore.purgeExpired, getPurgeInterval(config.ttlMs)).unref();

  return app;
}

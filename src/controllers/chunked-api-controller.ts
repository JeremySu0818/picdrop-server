import type { Request, Response } from 'express';

import {
  CHUNK_SIZE_BYTES,
  isStoreError,
  type ChunkedFileInit,
  type UploadStore,
} from '../services/upload-store.js';
import {
  INVALID_JSON,
  PAYLOAD_TOO_LARGE,
  readJsonBody,
} from '../utils/http-body.js';
import { parseByteRange } from '../utils/http-range.js';
import { isBase64, isLookupKey } from '../utils/validators.js';

const FILE_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

type ControllerOptions = {
  store: UploadStore;
  maxJsonBytes: number;
};

function sendResult(res: Response, result: unknown, successStatus = 200) {
  if (isStoreError(result)) {
    res.status(result.status).json({ error: result.error });
    return;
  }
  res.status(successStatus).json(result);
}

function parseFiles(value: unknown): ChunkedFileInit[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > 100) {
    return null;
  }
  const files: ChunkedFileInit[] = [];
  for (const item of value) {
    if (!item || typeof item !== 'object') return null;
    const file = item as Record<string, unknown>;
    const id = String(file.id || '');
    const size = Number(file.size);
    const chunkCount = Number(file.chunkCount);
    const metaIv = file.metaIv;
    const metaCiphertext = file.metaCiphertext;
    const expectedChunks = Math.max(1, Math.ceil(size / CHUNK_SIZE_BYTES));
    if (
      !FILE_ID_PATTERN.test(id) ||
      !Number.isSafeInteger(size) ||
      size < 0 ||
      !Number.isSafeInteger(chunkCount) ||
      chunkCount !== expectedChunks ||
      !isBase64(metaIv) ||
      !isBase64(metaCiphertext)
    ) {
      return null;
    }
    files.push({ id, size, chunkCount, metaIv, metaCiphertext });
  }
  if (new Set(files.map((file) => file.id)).size !== files.length) return null;
  return files;
}

async function readSmallJson(
  req: Request,
  res: Response,
  maxJsonBytes: number,
) {
  try {
    return await readJsonBody(req, Math.min(maxJsonBytes, 1024 * 1024));
  } catch (error) {
    const message =
      error instanceof Error && error.message === PAYLOAD_TOO_LARGE
        ? 'JSON body exceeds the configured limit.'
        : error instanceof Error && error.message === INVALID_JSON
          ? 'Invalid JSON body.'
          : 'Unable to read request body.';
    res
      .status(
        error instanceof Error && error.message === PAYLOAD_TOO_LARGE
          ? 413
          : 400,
      )
      .json({ error: message });
    return null;
  }
}

function bearerToken(req: Request): string {
  return String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
}

export function createChunkedApiController({
  store,
  maxJsonBytes,
}: ControllerOptions) {
  return {
    async createUpload(req: Request, res: Response) {
      const body = await readSmallJson(req, res, maxJsonBytes);
      if (!body) return;
      const lookupKey = String(body.lookupKey || '').toLowerCase();
      const files = parseFiles(body.files);
      if (!isLookupKey(lookupKey) || !files) {
        res.status(400).json({ error: 'Invalid chunked upload manifest.' });
        return;
      }
      sendResult(res, store.createChunkedUpload(lookupKey, files), 201);
    },

    async uploadChunk(req: Request, res: Response) {
      const index = Number(req.params.index);
      const iv = String(req.headers['x-chunk-iv'] || '');
      const contentLength = Number(req.headers['content-length']);
      if (!isBase64(iv) || !Number.isSafeInteger(contentLength)) {
        req.resume();
        res
          .status(400)
          .json({ error: 'Chunk IV and Content-Length are required.' });
        return;
      }
      const target = store.beginChunk(
        req.params.uploadId,
        req.params.fileId,
        index,
        iv,
        contentLength,
      );
      if (isStoreError(target)) {
        req.resume();
        sendResult(res, target);
        return;
      }

      try {
        let receivedBytes = 0;
        for await (const chunk of req) {
          if (receivedBytes + chunk.byteLength > contentLength) {
            throw new Error('Chunk exceeded its declared Content-Length.');
          }
          store.appendChunkPart(
            req.params.uploadId,
            req.params.fileId,
            index,
            chunk,
          );
          receivedBytes += chunk.byteLength;
        }
        if (receivedBytes !== contentLength) {
          throw new Error('Chunk did not match its declared Content-Length.');
        }
        sendResult(
          res,
          store.finishChunk(req.params.uploadId, req.params.fileId, index),
        );
      } catch (error) {
        store.failChunk(req.params.uploadId, req.params.fileId, index);
        res.status(400).json({ error: 'Unable to read encrypted chunk.' });
      }
    },

    async completeUpload(req: Request, res: Response) {
      const body = await readSmallJson(req, res, maxJsonBytes);
      if (!body) return;
      sendResult(res, store.completeChunkedUpload(String(body.uploadId || '')));
    },

    abortUpload(req: Request, res: Response) {
      sendResult(res, store.abortChunkedUpload(req.params.uploadId));
    },

    async getDownloadStatus(req: Request, res: Response) {
      const body = await readSmallJson(req, res, maxJsonBytes);
      if (!body) return;
      const lookupKey = String(body.lookupKey || '').toLowerCase();
      if (!isLookupKey(lookupKey)) {
        res
          .status(400)
          .json({ error: 'lookupKey must be a SHA-256 hex digest.' });
        return;
      }
      sendResult(res, store.getDownloadStatus(lookupKey));
    },

    async beginDownload(req: Request, res: Response) {
      const body = await readSmallJson(req, res, maxJsonBytes);
      if (!body) return;
      const lookupKey = String(body.lookupKey || '').toLowerCase();
      if (!isLookupKey(lookupKey)) {
        res
          .status(400)
          .json({ error: 'lookupKey must be a SHA-256 hex digest.' });
        return;
      }
      sendResult(res, store.beginChunkedDownload(lookupKey));
    },

    downloadChunk(req: Request, res: Response) {
      const chunk = store.acquireChunkedDownloadChunk(
        req.params.downloadId,
        bearerToken(req),
        req.params.fileId,
        Number(req.params.index),
      );
      if (isStoreError(chunk)) {
        sendResult(res, chunk);
        return;
      }

      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        store.releaseChunkedDownloadChunk(
          req.params.downloadId,
          bearerToken(req),
        );
      };
      res.once('finish', release);
      res.once('close', release);

      const totalLength = chunk.bytes.byteLength;
      const range = parseByteRange(req.headers.range, totalLength);
      if (range.kind === 'invalid') {
        res
          .status(416)
          .set({
            'Accept-Ranges': 'bytes',
            'Cache-Control': 'no-store',
            'Content-Range': `bytes */${totalLength}`,
          })
          .end();
        return;
      }

      const start = range.kind === 'range' ? range.start : 0;
      const end = range.kind === 'range' ? range.end : totalLength - 1;
      const responseBytes = chunk.bytes.subarray(start, end + 1);
      if (range.kind === 'range') {
        res.status(206);
      }
      res.set({
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'no-store',
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(responseBytes.byteLength),
        ...(range.kind === 'range'
          ? { 'Content-Range': `bytes ${start}-${end}/${totalLength}` }
          : {}),
        'X-Chunk-IV': chunk.iv,
      });
      res.end(responseBytes);
    },

    finishDownload(req: Request, res: Response) {
      sendResult(
        res,
        store.finishChunkedDownload(req.params.downloadId, bearerToken(req)),
      );
    },
  };
}

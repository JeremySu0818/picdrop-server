import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

import type { Request, Response } from 'express';

import { createChunkedApiController } from '../src/controllers/chunked-api-controller.js';
import type { UploadStore } from '../src/services/upload-store.js';

class MockResponse extends EventEmitter {
  body?: Uint8Array;
  headers: Record<string, string> = {};
  statusCode = 200;

  status(code: number) {
    this.statusCode = code;
    return this;
  }

  set(headers: Record<string, string>) {
    Object.assign(this.headers, headers);
    return this;
  }

  end(body?: Uint8Array) {
    this.body = body;
    this.emit('finish');
    return this;
  }
}

function runDownload(range?: string) {
  const bytes = Uint8Array.from({ length: 10 }, (_, index) => index);
  let releases = 0;
  const store = {
    acquireChunkedDownloadChunk(
      downloadId: string,
      token: string,
      fileId: string,
      index: number,
    ) {
      assert.deepEqual([downloadId, token, fileId, index], [
        'download-1',
        'token-1',
        'file-1',
        0,
      ]);
      return { iv: 'chunk-iv', bytes };
    },
    releaseChunkedDownloadChunk(downloadId: string, token: string) {
      assert.deepEqual([downloadId, token], ['download-1', 'token-1']);
      releases += 1;
    },
  } as UploadStore;
  const controller = createChunkedApiController({
    store,
    maxJsonBytes: 1024,
  });
  const req = {
    headers: {
      authorization: 'Bearer token-1',
      ...(range ? { range } : {}),
    },
    params: { downloadId: 'download-1', fileId: 'file-1', index: '0' },
  } as unknown as Request;
  const res = new MockResponse();

  controller.downloadChunk(req, res as unknown as Response);
  return { releases, res };
}

test('streams the complete chunk with byte-range capability advertised', () => {
  const { releases, res } = runDownload();

  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['Accept-Ranges'], 'bytes');
  assert.equal(res.headers['Content-Length'], '10');
  assert.deepEqual(res.body, Uint8Array.from({ length: 10 }, (_, index) => index));
  assert.equal(releases, 1);
});

test('streams a requested chunk tail as partial content', () => {
  const { releases, res } = runDownload('bytes=4-');

  assert.equal(res.statusCode, 206);
  assert.equal(res.headers['Accept-Ranges'], 'bytes');
  assert.equal(res.headers['Content-Length'], '6');
  assert.equal(res.headers['Content-Range'], 'bytes 4-9/10');
  assert.deepEqual(res.body, Uint8Array.from([4, 5, 6, 7, 8, 9]));
  assert.equal(releases, 1);
});

test('rejects an unsatisfiable range and still releases the chunk lease', () => {
  const { releases, res } = runDownload('bytes=10-');

  assert.equal(res.statusCode, 416);
  assert.equal(res.headers['Accept-Ranges'], 'bytes');
  assert.equal(res.headers['Content-Range'], 'bytes */10');
  assert.equal(res.body, undefined);
  assert.equal(releases, 1);
});

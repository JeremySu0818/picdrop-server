import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type {
  EncryptedFilePayload,
  ValidatedEncryptedPayload,
} from '../types.js';

export const CHUNK_SIZE_BYTES = 64 * 1024 * 1024;

export type ChunkedFileInit = {
  id: string;
  size: number;
  chunkCount: number;
  metaIv: string;
  metaCiphertext: string;
};

type UploadInsertPayload = {
  ok: true;
  expiresAt: number;
  files: number;
};

type UploadErrorPayload = {
  error: string;
};

export type UploadStoreStats = {
  uploadCount: number;
  fileCount: number;
  encryptedBytes: number;
};

type NativeResult<T> = {
  status: number;
  payload: T;
};

type NativeUploadStore = {
  abortChunkedUpload: (
    uploadId: string,
  ) => NativeResult<UploadErrorPayload | { ok: true }>;
  acquireChunkedDownloadChunk: (
    downloadId: string,
    token: string,
    fileId: string,
    index: number,
  ) => NativeResult<UploadErrorPayload | { iv: string; bytes: Uint8Array }>;
  appendChunkPart: (
    uploadId: string,
    fileId: string,
    index: number,
    bytes: Uint8Array,
  ) => void;
  beginChunk: (
    uploadId: string,
    fileId: string,
    index: number,
    iv: string,
    contentLength: number,
  ) => NativeResult<UploadErrorPayload | { ok: true }>;
  beginChunkedDownload: (lookupKey: string) => NativeResult<
    | UploadErrorPayload
    | {
        downloadId: string;
        downloadToken: string;
        files: ChunkedFileInit[];
      }
  >;
  clearUploads: () => number;
  completeChunkedUpload: (
    uploadId: string,
  ) => NativeResult<UploadErrorPayload | { ok: true; expiresAt: number }>;
  createChunkedUpload: (
    lookupKey: string,
    files: ChunkedFileInit[],
  ) => NativeResult<
    | UploadErrorPayload
    | { uploadId: string; expiresAt: number; chunkSize: number }
  >;
  failChunk: (uploadId: string, fileId: string, index: number) => void;
  finishChunk: (
    uploadId: string,
    fileId: string,
    index: number,
  ) => NativeResult<UploadErrorPayload | { ok: true }>;
  finishChunkedDownload: (
    downloadId: string,
    token: string,
  ) => NativeResult<UploadErrorPayload | { ok: true }>;
  getStats: () => UploadStoreStats;
  getDownloadStatus: (
    lookupKey: string,
  ) => NativeResult<
    UploadErrorPayload | { ok: true; expiresAt: number; fileCount: number }
  >;
  purgeExpired: () => number;
  releaseChunkedDownloadChunk: (downloadId: string, token: string) => void;
  takeDownload: (
    lookupKey: string,
  ) => NativeResult<UploadErrorPayload | { files: EncryptedFilePayload[] }>;
  upsertUpload: (
    lookupKey: string,
    files: EncryptedFilePayload[],
  ) => NativeResult<UploadErrorPayload | UploadInsertPayload>;
};

type NativeAddon = {
  createUploadStore: (ttlMs: number) => NativeUploadStore;
};

type UploadStoreDependencies = {
  ttlMs: number;
};

export type UploadStore = {
  abortChunkedUpload: (uploadId: string) => StoreResult<{ ok: true }>;
  acquireChunkedDownloadChunk: (
    downloadId: string,
    token: string,
    fileId: string,
    index: number,
  ) => StoreResult<{ iv: string; bytes: Uint8Array }>;
  appendChunkPart: (
    uploadId: string,
    fileId: string,
    index: number,
    bytes: Uint8Array,
  ) => void;
  beginChunk: (
    uploadId: string,
    fileId: string,
    index: number,
    iv: string,
    contentLength: number,
  ) => StoreResult<{ ok: true }>;
  beginChunkedDownload: (lookupKey: string) => StoreResult<{
    downloadId: string;
    downloadToken: string;
    files: ChunkedFileInit[];
  }>;
  clearUploads: () => number;
  completeChunkedUpload: (
    uploadId: string,
  ) => StoreResult<{ ok: true; expiresAt: number }>;
  createChunkedUpload: (
    lookupKey: string,
    files: ChunkedFileInit[],
  ) => StoreResult<{
    uploadId: string;
    expiresAt: number;
    chunkSize: number;
  }>;
  failChunk: (uploadId: string, fileId: string, index: number) => void;
  finishChunk: (
    uploadId: string,
    fileId: string,
    index: number,
  ) => StoreResult<{ ok: true }>;
  finishChunkedDownload: (
    downloadId: string,
    token: string,
  ) => StoreResult<{ ok: true }>;
  getStats: () => UploadStoreStats;
  getDownloadStatus: (
    lookupKey: string,
  ) => StoreResult<{ ok: true; expiresAt: number; fileCount: number }>;
  purgeExpired: () => void;
  releaseChunkedDownloadChunk: (downloadId: string, token: string) => void;
  takeDownload: (
    lookupKey: string,
  ) => NativeResult<UploadErrorPayload | { files: EncryptedFilePayload[] }>;
  upsertUpload: (
    parsed: ValidatedEncryptedPayload,
  ) => NativeResult<UploadErrorPayload | UploadInsertPayload>;
};

export type StoreError = {
  status: number;
  error: string;
};

export type StoreResult<T> = T | StoreError;

export function isStoreError(value: unknown): value is StoreError {
  return Boolean(
    value && typeof value === 'object' && 'status' in value && 'error' in value,
  );
}

function unwrapNativeResult<T>(
  result: NativeResult<T | UploadErrorPayload>,
): StoreResult<T> {
  if (result.status >= 400) {
    const payload = result.payload as UploadErrorPayload;
    return { status: result.status, error: payload.error };
  }
  return result.payload as T;
}

let cachedAddon: NativeAddon | undefined;

function loadNativeAddon(): NativeAddon {
  if (cachedAddon) {
    return cachedAddon;
  }

  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    process.env.DROP_NATIVE_ADDON_PATH,
    path.resolve(process.cwd(), 'build/Release/drop_core.node'),
    path.resolve(moduleDir, '../../build/Release/drop_core.node'),
    path.resolve(moduleDir, '../../../build/Release/drop_core.node'),
  ].filter((candidate): candidate is string => Boolean(candidate));
  const require = createRequire(import.meta.url);
  const failures: string[] = [];

  for (const candidate of [...new Set(candidates)]) {
    try {
      cachedAddon = require(candidate) as NativeAddon;
      return cachedAddon;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      failures.push(`${candidate}: ${message}`);
    }
  }

  throw new Error(
    [
      'Unable to load the Drop native security core.',
      'Run "npm run build:native" before starting the server.',
      ...failures,
    ].join('\n'),
  );
}

export function createUploadStore({
  ttlMs,
}: UploadStoreDependencies): UploadStore {
  const nativeStore = loadNativeAddon().createUploadStore(ttlMs);

  return {
    abortChunkedUpload: (uploadId) =>
      unwrapNativeResult(nativeStore.abortChunkedUpload(uploadId)),
    acquireChunkedDownloadChunk: (downloadId, token, fileId, index) =>
      unwrapNativeResult(
        nativeStore.acquireChunkedDownloadChunk(
          downloadId,
          token,
          fileId,
          index,
        ),
      ),
    appendChunkPart: (uploadId, fileId, index, bytes) =>
      nativeStore.appendChunkPart(uploadId, fileId, index, bytes),
    beginChunk: (uploadId, fileId, index, iv, contentLength) =>
      unwrapNativeResult(
        nativeStore.beginChunk(uploadId, fileId, index, iv, contentLength),
      ),
    beginChunkedDownload: (lookupKey) =>
      unwrapNativeResult(nativeStore.beginChunkedDownload(lookupKey)),
    clearUploads: () => nativeStore.clearUploads(),
    completeChunkedUpload: (uploadId) =>
      unwrapNativeResult(nativeStore.completeChunkedUpload(uploadId)),
    createChunkedUpload: (lookupKey, files) =>
      unwrapNativeResult(nativeStore.createChunkedUpload(lookupKey, files)),
    failChunk: (uploadId, fileId, index) =>
      nativeStore.failChunk(uploadId, fileId, index),
    finishChunk: (uploadId, fileId, index) =>
      unwrapNativeResult(nativeStore.finishChunk(uploadId, fileId, index)),
    finishChunkedDownload: (downloadId, token) =>
      unwrapNativeResult(nativeStore.finishChunkedDownload(downloadId, token)),
    getStats: () => nativeStore.getStats(),
    getDownloadStatus: (lookupKey) =>
      unwrapNativeResult(nativeStore.getDownloadStatus(lookupKey)),
    purgeExpired: () => {
      nativeStore.purgeExpired();
    },
    releaseChunkedDownloadChunk: (downloadId, token) =>
      nativeStore.releaseChunkedDownloadChunk(downloadId, token),
    takeDownload: (lookupKey) => nativeStore.takeDownload(lookupKey),
    upsertUpload: (parsed) =>
      nativeStore.upsertUpload(parsed.key, parsed.files),
  };
}

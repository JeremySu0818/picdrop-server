#include "core/upload_store.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <random>
#include <stdexcept>
#include <utility>

namespace drop_server {
namespace {

constexpr const char *kNotFoundMessage =
    "File not found. It may have already been downloaded or expired.";
constexpr const char *kExpiredMessage = "File has expired.";

std::string MakeSecret() {
  static constexpr char hexadecimal[] = "0123456789abcdef";
  std::random_device random;
  std::array<std::uint8_t, 32> bytes{};
  for (auto &byte : bytes) {
    byte = static_cast<std::uint8_t>(random());
  }
  std::string result;
  result.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    result.push_back(hexadecimal[(byte >> 4U) & 0x0fU]);
    result.push_back(hexadecimal[byte & 0x0fU]);
  }
  SecureZero(bytes.data(), bytes.size());
  return result;
}

} // namespace

std::int64_t NowMilliseconds() noexcept {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

UploadStore::UploadStore(std::int64_t ttl_ms) : ttl_ms_(ttl_ms) {}

std::size_t UploadStore::PurgeExpired(std::int64_t now) {
  std::size_t purged = 0;
  for (auto iterator = uploads_.begin(); iterator != uploads_.end();) {
    if (iterator->second.expires_at <= now) {
      iterator = uploads_.erase(iterator);
      ++purged;
    } else {
      ++iterator;
    }
  }
  for (auto iterator = chunked_uploads_.begin();
       iterator != chunked_uploads_.end();) {
    if (iterator->second.pending_delete || iterator->second.expires_at > now ||
        iterator->second.active_leases > 0) {
      ++iterator;
      continue;
    }
    chunked_lookup_.erase(iterator->second.lookup_key);
    iterator = chunked_uploads_.erase(iterator);
    ++purged;
  }
  if (purged > 0) {
    ReleaseUnusedMemory();
  }
  return purged;
}

UpsertResult UploadStore::Upsert(std::string key,
                                 std::vector<EncryptedFile> files,
                                 std::size_t incoming_bytes) {
  const std::int64_t now = NowMilliseconds();
  PurgeExpired(now);

  auto existing = uploads_.find(key);
  if (existing != uploads_.end()) {
    auto &record = existing->second;
    record.files.reserve(record.files.size() + files.size());
    for (auto &file : files) {
      record.files.push_back(std::move(file));
    }
    record.bytes += incoming_bytes;
    return {{200, nullptr}, record.expires_at, record.files.size()};
  }

  const std::int64_t expires_at =
      now > std::numeric_limits<std::int64_t>::max() - ttl_ms_
          ? std::numeric_limits<std::int64_t>::max()
          : now + ttl_ms_;
  const std::size_t incoming_file_count = files.size();
  UploadRecord record{
      std::move(files),
      now,
      expires_at,
      incoming_bytes,
  };
  uploads_.emplace(std::move(key), std::move(record));
  return {{201, nullptr}, expires_at, incoming_file_count};
}

TakeResult UploadStore::Take(const std::string &key) {
  auto iterator = uploads_.find(key);
  if (iterator == uploads_.end()) {
    return {{404, kNotFoundMessage}, {}};
  }

  auto record_node = uploads_.extract(iterator);
  UploadRecord &record = record_node.mapped();
  if (record.expires_at <= NowMilliseconds()) {
    record.files.clear();
    ReleaseUnusedMemory();
    return {{410, kExpiredMessage}, {}};
  }

  TakeResult result{{200, nullptr}, std::move(record.files)};
  return result;
}

std::size_t UploadStore::Clear() {
  const std::size_t cleared = uploads_.size() + chunked_uploads_.size();
  uploads_.clear();
  chunked_lookup_.clear();
  for (auto iterator = chunked_uploads_.begin();
       iterator != chunked_uploads_.end();) {
    if (iterator->second.active_leases > 0) {
      iterator->second.pending_delete = true;
      ++iterator;
    } else {
      iterator = chunked_uploads_.erase(iterator);
    }
  }
  ReleaseUnusedMemory();
  return cleared;
}

Stats UploadStore::GetStats() {
  PurgeExpired(NowMilliseconds());
  Stats stats;
  stats.upload_count = uploads_.size() + chunked_uploads_.size();
  for (const auto &entry : uploads_) {
    stats.file_count += entry.second.files.size();
    stats.encrypted_bytes += entry.second.bytes;
  }
  for (const auto &entry : chunked_uploads_) {
    stats.file_count += entry.second.files.size();
    for (const auto &file : entry.second.files) {
      stats.encrypted_bytes +=
          file.meta_iv.size() + file.meta_ciphertext.size();
      for (const auto &chunk : file.chunks) {
        stats.encrypted_bytes += chunk.iv.size() + chunk.ciphertext.size();
      }
    }
  }
  return stats;
}

CreateChunkedUploadResult
UploadStore::CreateChunkedUpload(std::string lookup_key,
                                 std::vector<ChunkedFile> files) {
  PurgeExpired(NowMilliseconds());
  if (uploads_.find(lookup_key) != uploads_.end() ||
      chunked_lookup_.find(lookup_key) != chunked_lookup_.end()) {
    return {{409, "An upload already exists for this code."}, {}, 0};
  }

  std::string upload_id;
  do {
    upload_id = MakeSecret();
  } while (chunked_uploads_.find(upload_id) != chunked_uploads_.end());

  ChunkedSession session;
  session.lookup_key = std::move(lookup_key);
  session.expires_at = ExpiryFromNow();
  session.files = std::move(files);
  const std::string lookup_copy = session.lookup_key;
  const std::int64_t expires_at = session.expires_at;
  chunked_uploads_.emplace(upload_id, std::move(session));
  chunked_lookup_.emplace(lookup_copy, upload_id);
  return {{201, nullptr}, std::move(upload_id), expires_at};
}

StatusResult UploadStore::BeginChunk(const std::string &upload_id,
                                     const std::string &file_id,
                                     std::uint32_t index, SecureBytes iv,
                                     std::size_t content_length) {
  ChunkedSession *session = FindChunkedSession(upload_id);
  if (session == nullptr || session->expires_at <= NowMilliseconds()) {
    if (session != nullptr) {
      EraseChunkedUpload(upload_id);
    }
    return {404, "Upload session not found or expired."};
  }
  if (session->state != ChunkedSessionState::Uploading ||
      session->pending_delete) {
    return {409, "Upload session is no longer writable."};
  }
  ChunkedFile *file = FindChunkedFile(*session, file_id);
  if (file == nullptr || index >= file->chunk_count) {
    return {400, "Invalid file chunk."};
  }
  EncryptedChunk &chunk = file->chunks[index];
  if (chunk.complete || chunk.receiving) {
    return {409, "This chunk was already uploaded."};
  }
  if (iv.size() != 12 || content_length != ExpectedChunkBytes(*file, index)) {
    return {400, "Encrypted chunk size or IV is invalid."};
  }

  chunk.iv = std::move(iv);
  chunk.ciphertext = SecureBytes(content_length);
  chunk.written = 0;
  chunk.receiving = true;
  Touch(*session);
  return {};
}

void UploadStore::AppendChunkPart(const std::string &upload_id,
                                  const std::string &file_id,
                                  std::uint32_t index, const ByteView &bytes) {
  ChunkedSession *session = FindChunkedSession(upload_id);
  ChunkedFile *file =
      session == nullptr ? nullptr : FindChunkedFile(*session, file_id);
  if (session == nullptr || file == nullptr || index >= file->chunk_count) {
    throw std::runtime_error("Upload session or file chunk was not found.");
  }
  EncryptedChunk &chunk = file->chunks[index];
  if (!chunk.receiving || chunk.complete ||
      bytes.size > chunk.ciphertext.size() - chunk.written) {
    throw std::runtime_error("Encrypted chunk stream is invalid.");
  }
  chunk.ciphertext.CopyAt(chunk.written, bytes.data, bytes.size);
  chunk.written += bytes.size;
  Touch(*session);
}

StatusResult UploadStore::FinishChunk(const std::string &upload_id,
                                      const std::string &file_id,
                                      std::uint32_t index) {
  ChunkedSession *session = FindChunkedSession(upload_id);
  ChunkedFile *file =
      session == nullptr ? nullptr : FindChunkedFile(*session, file_id);
  if (session == nullptr || file == nullptr || index >= file->chunk_count) {
    return {404, "Upload session not found or expired."};
  }
  EncryptedChunk &chunk = file->chunks[index];
  if (!chunk.receiving || chunk.written != chunk.ciphertext.size()) {
    return {400, "Encrypted chunk ended before completion."};
  }
  chunk.receiving = false;
  chunk.complete = true;
  Touch(*session);
  return {};
}

void UploadStore::FailChunk(const std::string &upload_id,
                            const std::string &file_id, std::uint32_t index) {
  ChunkedSession *session = FindChunkedSession(upload_id);
  ChunkedFile *file =
      session == nullptr ? nullptr : FindChunkedFile(*session, file_id);
  if (session == nullptr || file == nullptr || index >= file->chunk_count) {
    return;
  }
  EncryptedChunk &chunk = file->chunks[index];
  chunk.iv.Reset();
  chunk.ciphertext.Reset();
  chunk.written = 0;
  chunk.receiving = false;
  chunk.complete = false;
  Touch(*session);
  ReleaseUnusedMemory();
}

CompleteChunkedUploadResult
UploadStore::CompleteChunkedUpload(const std::string &upload_id) {
  ChunkedSession *session = FindChunkedSession(upload_id);
  if (session == nullptr || session->expires_at <= NowMilliseconds()) {
    if (session != nullptr) {
      EraseChunkedUpload(upload_id);
    }
    return {{404, "Upload session not found or expired."}, 0};
  }
  if (session->state != ChunkedSessionState::Uploading) {
    return {{409, "Upload was already completed."}, 0};
  }
  for (const auto &file : session->files) {
    for (const auto &chunk : file.chunks) {
      if (!chunk.complete || chunk.receiving) {
        return {{409, "Not all file chunks were uploaded."}, 0};
      }
    }
  }
  session->state = ChunkedSessionState::Ready;
  Touch(*session);
  return {{200, nullptr}, session->expires_at};
}

DownloadStatusResult
UploadStore::GetDownloadStatus(const std::string &lookup_key) {
  const std::int64_t now = NowMilliseconds();
  const auto chunked_lookup = chunked_lookup_.find(lookup_key);
  if (chunked_lookup != chunked_lookup_.end()) {
    ChunkedSession *session = FindChunkedSession(chunked_lookup->second);
    if (session == nullptr || session->pending_delete) {
      return {{404, kNotFoundMessage}, 0, 0};
    }
    if (session->expires_at <= now) {
      EraseChunkedUpload(chunked_lookup->second);
      return {{410, kExpiredMessage}, 0, 0};
    }
    if (session->state == ChunkedSessionState::Ready ||
        session->state == ChunkedSessionState::Downloading) {
      return {{200, nullptr}, session->expires_at, session->files.size()};
    }
    return {{409, "Upload is still being prepared."}, session->expires_at,
            session->files.size()};
  }

  const auto legacy_upload = uploads_.find(lookup_key);
  if (legacy_upload == uploads_.end()) {
    return {{404, kNotFoundMessage}, 0, 0};
  }
  if (legacy_upload->second.expires_at <= now) {
    uploads_.erase(legacy_upload);
    ReleaseUnusedMemory();
    return {{410, kExpiredMessage}, 0, 0};
  }
  return {{200, nullptr}, legacy_upload->second.expires_at,
          legacy_upload->second.files.size()};
}

BeginChunkedDownloadResult
UploadStore::BeginChunkedDownload(const std::string &lookup_key) {
  constexpr const char *error =
      "Upload not found, expired, or already claimed.";
  PurgeExpired(NowMilliseconds());
  const auto lookup = chunked_lookup_.find(lookup_key);
  if (lookup == chunked_lookup_.end()) {
    return {{404, error}, {}, {}, nullptr};
  }
  ChunkedSession *session = FindChunkedSession(lookup->second);
  if (session == nullptr || session->pending_delete ||
      (session->state != ChunkedSessionState::Ready &&
       session->state != ChunkedSessionState::Downloading)) {
    return {{404, error}, {}, {}, nullptr};
  }
  if (session->state == ChunkedSessionState::Ready) {
    session->state = ChunkedSessionState::Downloading;
    session->download_token = MakeSecret();
  }
  Touch(*session);
  return {
      {200, nullptr}, lookup->second, session->download_token, &session->files};
}

AcquireChunkResult UploadStore::AcquireChunkedDownloadChunk(
    const std::string &download_id, const std::string &token,
    const std::string &file_id, std::uint32_t index) {
  ChunkedSession *session = FindChunkedSession(download_id);
  if (session == nullptr || session->expires_at <= NowMilliseconds() ||
      session->pending_delete ||
      session->state != ChunkedSessionState::Downloading ||
      session->download_token != token) {
    return {{404, "Download session not found or expired."}, nullptr};
  }
  ChunkedFile *file = FindChunkedFile(*session, file_id);
  if (file == nullptr || index >= file->chunk_count ||
      !file->chunks[index].complete) {
    return {{404, "File chunk not found."}, nullptr};
  }
  EncryptedChunk &chunk = file->chunks[index];
  session->active_leases += 1;
  Touch(*session);
  return {{200, nullptr}, &chunk};
}

void UploadStore::ReleaseChunkedDownloadChunk(const std::string &download_id,
                                              const std::string &token) {
  auto iterator = chunked_uploads_.find(download_id);
  if (iterator == chunked_uploads_.end() ||
      iterator->second.download_token != token ||
      iterator->second.active_leases == 0) {
    return;
  }
  iterator->second.active_leases -= 1;
  if (iterator->second.active_leases == 0) {
    if (iterator->second.pending_delete) {
      chunked_lookup_.erase(iterator->second.lookup_key);
      chunked_uploads_.erase(iterator);
      ReleaseUnusedMemory();
    } else {
      Touch(iterator->second);
    }
  }
}

StatusResult UploadStore::FinishChunkedDownload(const std::string &download_id,
                                                const std::string &token) {
  auto iterator = chunked_uploads_.find(download_id);
  if (iterator == chunked_uploads_.end() ||
      iterator->second.state != ChunkedSessionState::Downloading ||
      iterator->second.download_token != token) {
    return {404, "Download session not found or expired."};
  }
  chunked_lookup_.erase(iterator->second.lookup_key);
  if (iterator->second.active_leases > 0) {
    iterator->second.pending_delete = true;
  } else {
    chunked_uploads_.erase(iterator);
    ReleaseUnusedMemory();
  }
  return {};
}

StatusResult UploadStore::AbortChunkedUpload(const std::string &upload_id) {
  auto iterator = chunked_uploads_.find(upload_id);
  if (iterator == chunked_uploads_.end() ||
      iterator->second.state != ChunkedSessionState::Uploading) {
    return {404, "Upload session not found."};
  }
  chunked_lookup_.erase(iterator->second.lookup_key);
  chunked_uploads_.erase(iterator);
  ReleaseUnusedMemory();
  return {};
}

std::int64_t UploadStore::ExpiryFromNow() const noexcept {
  const std::int64_t now = NowMilliseconds();
  return now > std::numeric_limits<std::int64_t>::max() - ttl_ms_
             ? std::numeric_limits<std::int64_t>::max()
             : now + ttl_ms_;
}

void UploadStore::Touch(ChunkedSession &session) const noexcept {
  session.expires_at = ExpiryFromNow();
}

std::size_t UploadStore::ExpectedChunkBytes(const ChunkedFile &file,
                                            std::uint32_t index) {
  const std::uint64_t offset =
      static_cast<std::uint64_t>(index) * kChunkSizeBytes;
  const std::uint64_t plaintext =
      std::min<std::uint64_t>(kChunkSizeBytes, file.size - offset);
  return static_cast<std::size_t>(plaintext) + kGcmTagBytes;
}

ChunkedSession *UploadStore::FindChunkedSession(const std::string &id) {
  const auto iterator = chunked_uploads_.find(id);
  return iterator == chunked_uploads_.end() ? nullptr : &iterator->second;
}

ChunkedFile *UploadStore::FindChunkedFile(ChunkedSession &session,
                                          const std::string &id) {
  for (auto &file : session.files) {
    if (file.id == id) {
      return &file;
    }
  }
  return nullptr;
}

void UploadStore::EraseChunkedUpload(const std::string &id) {
  const auto iterator = chunked_uploads_.find(id);
  if (iterator == chunked_uploads_.end()) {
    return;
  }
  chunked_lookup_.erase(iterator->second.lookup_key);
  if (iterator->second.active_leases > 0) {
    iterator->second.pending_delete = true;
    return;
  }
  chunked_uploads_.erase(iterator);
  ReleaseUnusedMemory();
}

} // namespace drop_server

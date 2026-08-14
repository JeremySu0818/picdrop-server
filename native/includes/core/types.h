#ifndef DROP_SERVER_CORE_TYPES_H_
#define DROP_SERVER_CORE_TYPES_H_

#include "memory/secure_bytes.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace drop_server {

inline constexpr std::size_t kChunkSizeBytes = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t kGcmTagBytes = 16;

struct ByteView {
  const std::uint8_t *data = nullptr;
  std::size_t size = 0;
};

struct EncryptedFile {
  SecureBytes file_iv;
  SecureBytes file_ciphertext;
  SecureBytes meta_iv;
  SecureBytes meta_ciphertext;

  std::size_t ByteSize() const noexcept {
    return file_iv.size() + file_ciphertext.size() + meta_iv.size() +
           meta_ciphertext.size();
  }
};

struct UploadRecord {
  std::vector<EncryptedFile> files;
  std::int64_t created_at = 0;
  std::int64_t expires_at = 0;
  std::size_t bytes = 0;
};

struct EncryptedChunk {
  SecureBytes iv;
  SecureBytes ciphertext;
  std::size_t written = 0;
  bool receiving = false;
  bool complete = false;
};

struct ChunkedFile {
  std::string id;
  std::uint64_t size = 0;
  std::uint32_t chunk_count = 0;
  SecureBytes meta_iv;
  SecureBytes meta_ciphertext;
  std::vector<EncryptedChunk> chunks;
};

enum class ChunkedSessionState {
  Uploading,
  Ready,
  Downloading,
};

struct ChunkedSession {
  std::string lookup_key;
  std::int64_t expires_at = 0;
  ChunkedSessionState state = ChunkedSessionState::Uploading;
  std::string download_token;
  std::size_t active_leases = 0;
  bool pending_delete = false;
  std::vector<ChunkedFile> files;
};

struct StatusResult {
  int status = 200;
  const char *error = nullptr;
};

struct UpsertResult : StatusResult {
  std::int64_t expires_at = 0;
  std::size_t files = 0;
};

struct TakeResult : StatusResult {
  std::vector<EncryptedFile> files;
};

struct Stats {
  std::size_t upload_count = 0;
  std::size_t file_count = 0;
  std::size_t encrypted_bytes = 0;
};

struct CreateChunkedUploadResult : StatusResult {
  std::string upload_id;
  std::int64_t expires_at = 0;
};

struct CompleteChunkedUploadResult : StatusResult {
  std::int64_t expires_at = 0;
};

struct DownloadStatusResult : StatusResult {
  std::int64_t expires_at = 0;
  std::size_t file_count = 0;
};

struct BeginChunkedDownloadResult : StatusResult {
  std::string download_id;
  std::string download_token;
  const std::vector<ChunkedFile> *files = nullptr;
};

struct AcquireChunkResult : StatusResult {
  EncryptedChunk *chunk = nullptr;
};

} // namespace drop_server

#endif

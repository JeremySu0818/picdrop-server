#include "napi/napi_helpers.h"

#include <cmath>
#include <limits>
#include <utility>

namespace drop_server::napi {
namespace {

constexpr double kMaxSafeInteger = 9007199254740991.0;

bool SafeAdd(std::size_t left, std::size_t right,
             std::size_t *result) noexcept {
  if (right > std::numeric_limits<std::size_t>::max() - left) {
    return false;
  }
  *result = left + right;
  return true;
}

int Base64Value(unsigned char character) noexcept {
  if (character >= 'A' && character <= 'Z') {
    return character - 'A';
  }
  if (character >= 'a' && character <= 'z') {
    return character - 'a' + 26;
  }
  if (character >= '0' && character <= '9') {
    return character - '0' + 52;
  }
  if (character == '+') {
    return 62;
  }
  if (character == '/') {
    return 63;
  }
  return -1;
}

bool DecodeBase64(const std::uint8_t *encoded, std::size_t encoded_size,
                  SecureBytes *output) {
  if (encoded_size == 0) {
    return false;
  }

  std::size_t padding = 0;
  while (padding < encoded_size && encoded[encoded_size - 1 - padding] == '=') {
    ++padding;
  }
  if (padding > 2 || (padding > 0 && encoded_size % 4 != 0)) {
    return false;
  }

  const std::size_t content_size = encoded_size - padding;
  if (content_size % 4 == 1) {
    return false;
  }
  for (std::size_t index = 0; index < content_size; ++index) {
    if (Base64Value(encoded[index]) < 0) {
      return false;
    }
  }
  for (std::size_t index = content_size; index < encoded_size; ++index) {
    if (encoded[index] != '=') {
      return false;
    }
  }

  if (content_size > std::numeric_limits<std::size_t>::max() / 6) {
    return false;
  }
  const std::size_t decoded_size = (content_size * 6) / 8;
  SecureBytes decoded(decoded_size);
  std::uint32_t accumulator = 0;
  int bits = 0;
  std::size_t output_index = 0;
  for (std::size_t index = 0; index < content_size; ++index) {
    accumulator = (accumulator << 6) |
                  static_cast<std::uint32_t>(Base64Value(encoded[index]));
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      decoded.data()[output_index++] =
          static_cast<std::uint8_t>((accumulator >> bits) & 0xffU);
    }
  }

  if (output_index != decoded_size) {
    return false;
  }
  *output = std::move(decoded);
  return true;
}

SecureBytes ReadBase64Property(napi_env env, napi_value object,
                               const char *property_name) {
  napi_value value;
  Check(env, napi_get_named_property(env, object, property_name, &value));

  napi_valuetype type;
  Check(env, napi_typeof(env, value, &type));
  if (type != napi_string) {
    const std::string message = std::string(property_name) + " must be base64.";
    ThrowTypeError(env, message.c_str());
  }

  std::size_t encoded_length = 0;
  Check(env,
        napi_get_value_string_utf8(env, value, nullptr, 0, &encoded_length));
  SecureBytes encoded(encoded_length + 1);
  std::size_t written = 0;
  Check(env, napi_get_value_string_utf8(
                 env, value, reinterpret_cast<char *>(encoded.data()),
                 encoded.size(), &written));

  SecureBytes decoded;
  if (written != encoded_length ||
      !DecodeBase64(encoded.data(), written, &decoded)) {
    const std::string message =
        std::string(property_name) + " must be valid base64.";
    ThrowTypeError(env, message.c_str());
  }
  return decoded;
}

EncryptedFile ReadEncryptedFile(napi_env env, napi_value value,
                                std::uint32_t index) {
  napi_valuetype type;
  Check(env, napi_typeof(env, value, &type));
  if (type != napi_object) {
    const std::string message =
        "files[" + std::to_string(index) + "] must be an object.";
    ThrowTypeError(env, message.c_str());
  }

  EncryptedFile file;
  file.file_iv = ReadBase64Property(env, value, "fileIv");
  file.file_ciphertext = ReadBase64Property(env, value, "fileCiphertext");
  file.meta_iv = ReadBase64Property(env, value, "metaIv");
  file.meta_ciphertext = ReadBase64Property(env, value, "metaCiphertext");
  return file;
}

napi_value MakeBoolean(napi_env env, bool value) {
  napi_value result;
  Check(env, napi_get_boolean(env, value, &result));
  return result;
}

napi_value MakeString(napi_env env, const char *value) {
  napi_value result;
  Check(env, napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &result));
  return result;
}

napi_value MakeString(napi_env env, const std::string &value) {
  napi_value result;
  Check(env, napi_create_string_utf8(env, value.data(), value.size(), &result));
  return result;
}

void SetProperty(napi_env env, napi_value object, const char *name,
                 napi_value value) {
  Check(env, napi_set_named_property(env, object, name, value));
}

napi_value MakeErrorPayload(napi_env env, const char *message) {
  napi_value payload;
  Check(env, napi_create_object(env, &payload));
  SetProperty(env, payload, "error", MakeString(env, message));
  return payload;
}

napi_value MakeResult(napi_env env, int status, napi_value payload) {
  napi_value result;
  Check(env, napi_create_object(env, &result));
  SetProperty(env, result, "status", MakeNumber(env, status));
  SetProperty(env, result, "payload", payload);
  return result;
}

napi_value MakeOkPayload(napi_env env) {
  napi_value payload;
  Check(env, napi_create_object(env, &payload));
  SetProperty(env, payload, "ok", MakeBoolean(env, true));
  return payload;
}

napi_value EncodeBase64(napi_env env, const SecureBytes &input) {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const std::size_t encoded_size = ((input.size() + 2) / 3) * 4;
  SecureBytes encoded(encoded_size);

  std::size_t input_index = 0;
  std::size_t output_index = 0;
  while (input_index + 3 <= input.size()) {
    const std::uint32_t block =
        (static_cast<std::uint32_t>(input.data()[input_index]) << 16) |
        (static_cast<std::uint32_t>(input.data()[input_index + 1]) << 8) |
        static_cast<std::uint32_t>(input.data()[input_index + 2]);
    encoded.data()[output_index++] = alphabet[(block >> 18) & 0x3fU];
    encoded.data()[output_index++] = alphabet[(block >> 12) & 0x3fU];
    encoded.data()[output_index++] = alphabet[(block >> 6) & 0x3fU];
    encoded.data()[output_index++] = alphabet[block & 0x3fU];
    input_index += 3;
  }

  const std::size_t remaining = input.size() - input_index;
  if (remaining == 1) {
    const std::uint32_t block =
        static_cast<std::uint32_t>(input.data()[input_index]) << 16;
    encoded.data()[output_index++] = alphabet[(block >> 18) & 0x3fU];
    encoded.data()[output_index++] = alphabet[(block >> 12) & 0x3fU];
    encoded.data()[output_index++] = '=';
    encoded.data()[output_index++] = '=';
  } else if (remaining == 2) {
    const std::uint32_t block =
        (static_cast<std::uint32_t>(input.data()[input_index]) << 16) |
        (static_cast<std::uint32_t>(input.data()[input_index + 1]) << 8);
    encoded.data()[output_index++] = alphabet[(block >> 18) & 0x3fU];
    encoded.data()[output_index++] = alphabet[(block >> 12) & 0x3fU];
    encoded.data()[output_index++] = alphabet[(block >> 6) & 0x3fU];
    encoded.data()[output_index++] = '=';
  }

  napi_value result;
  Check(env, napi_create_string_utf8(
                 env, reinterpret_cast<const char *>(encoded.data()),
                 encoded_size, &result));
  return result;
}

napi_value MakeFilePayload(napi_env env, const EncryptedFile &file) {
  napi_value result;
  Check(env, napi_create_object(env, &result));
  SetProperty(env, result, "fileIv", EncodeBase64(env, file.file_iv));
  SetProperty(env, result, "fileCiphertext",
              EncodeBase64(env, file.file_ciphertext));
  SetProperty(env, result, "metaIv", EncodeBase64(env, file.meta_iv));
  SetProperty(env, result, "metaCiphertext",
              EncodeBase64(env, file.meta_ciphertext));
  return result;
}

void NoopExternalBufferFinalizer(napi_env, void *, void *) {}

napi_value RenderErrorOrNull(napi_env env, const StatusResult &result) {
  return result.error == nullptr
             ? nullptr
             : MakeResult(env, result.status,
                          MakeErrorPayload(env, result.error));
}

} // namespace

NapiFailure::NapiFailure(const std::string &message)
    : std::runtime_error(message) {}

void Check(napi_env env, napi_status status) {
  if (status == napi_ok) {
    return;
  }
  if (status == napi_pending_exception) {
    throw PendingJavaScriptException{};
  }

  const napi_extended_error_info *info = nullptr;
  napi_get_last_error_info(env, &info);
  const char *message = info != nullptr && info->error_message != nullptr
                            ? info->error_message
                            : "Native N-API operation failed.";
  throw NapiFailure(message);
}

[[noreturn]] void ThrowTypeError(napi_env env, const char *message) {
  napi_throw_type_error(env, nullptr, message);
  throw PendingJavaScriptException{};
}

std::uint64_t ReadPositiveInteger(napi_env env, napi_value value,
                                  const char *name) {
  napi_valuetype type;
  Check(env, napi_typeof(env, value, &type));
  if (type != napi_number) {
    const std::string message = std::string(name) + " must be a number.";
    ThrowTypeError(env, message.c_str());
  }

  double number = 0;
  Check(env, napi_get_value_double(env, value, &number));
  if (!std::isfinite(number) || number <= 0 || std::floor(number) != number ||
      number > kMaxSafeInteger) {
    const std::string message =
        std::string(name) + " must be a positive safe integer.";
    ThrowTypeError(env, message.c_str());
  }
  return static_cast<std::uint64_t>(number);
}

std::uint64_t ReadNonNegativeInteger(napi_env env, napi_value value,
                                     const char *name) {
  napi_valuetype type;
  Check(env, napi_typeof(env, value, &type));
  if (type != napi_number) {
    const std::string message = std::string(name) + " must be a number.";
    ThrowTypeError(env, message.c_str());
  }

  double number = 0;
  Check(env, napi_get_value_double(env, value, &number));
  if (!std::isfinite(number) || number < 0 || std::floor(number) != number ||
      number > kMaxSafeInteger) {
    const std::string message =
        std::string(name) + " must be a non-negative safe integer.";
    ThrowTypeError(env, message.c_str());
  }
  return static_cast<std::uint64_t>(number);
}

std::string ReadString(napi_env env, napi_value value, const char *name) {
  napi_valuetype type;
  Check(env, napi_typeof(env, value, &type));
  if (type != napi_string) {
    const std::string message = std::string(name) + " must be a string.";
    ThrowTypeError(env, message.c_str());
  }

  std::size_t length = 0;
  Check(env, napi_get_value_string_utf8(env, value, nullptr, 0, &length));
  std::string result(length + 1, '\0');
  std::size_t written = 0;
  Check(env, napi_get_value_string_utf8(env, value, result.data(), length + 1,
                                        &written));
  result.resize(written);
  return result;
}

ByteView ReadByteView(napi_env env, napi_value value, const char *name) {
  bool is_buffer = false;
  Check(env, napi_is_buffer(env, value, &is_buffer));
  if (is_buffer) {
    void *data = nullptr;
    std::size_t size = 0;
    Check(env, napi_get_buffer_info(env, value, &data, &size));
    return {static_cast<const std::uint8_t *>(data), size};
  }

  bool is_typed_array = false;
  Check(env, napi_is_typedarray(env, value, &is_typed_array));
  if (is_typed_array) {
    napi_typedarray_type array_type;
    std::size_t length = 0;
    void *data = nullptr;
    napi_value array_buffer;
    std::size_t byte_offset = 0;
    Check(env, napi_get_typedarray_info(env, value, &array_type, &length, &data,
                                        &array_buffer, &byte_offset));
    if (array_type != napi_uint8_array &&
        array_type != napi_uint8_clamped_array) {
      const std::string message =
          std::string(name) + " must be an unsigned byte array.";
      ThrowTypeError(env, message.c_str());
    }
    return {static_cast<const std::uint8_t *>(data), length};
  }

  const std::string message =
      std::string(name) + " must be an unsigned byte array.";
  ThrowTypeError(env, message.c_str());
}

SecureBytes ReadBase64Value(napi_env env, napi_value value, const char *name) {
  const std::string encoded = ReadString(env, value, name);
  SecureBytes decoded;
  if (!DecodeBase64(reinterpret_cast<const std::uint8_t *>(encoded.data()),
                    encoded.size(), &decoded)) {
    const std::string message = std::string(name) + " must be valid base64.";
    ThrowTypeError(env, message.c_str());
  }
  return decoded;
}

std::vector<EncryptedFile> ReadFiles(napi_env env, napi_value value,
                                     std::size_t *byte_size) {
  bool is_array = false;
  Check(env, napi_is_array(env, value, &is_array));
  if (!is_array) {
    ThrowTypeError(env, "files must be an array.");
  }

  std::uint32_t length = 0;
  Check(env, napi_get_array_length(env, value, &length));
  if (length == 0) {
    ThrowTypeError(env, "files must include at least one encrypted file.");
  }

  std::vector<EncryptedFile> files;
  files.reserve(length);
  std::size_t total = 0;
  for (std::uint32_t index = 0; index < length; ++index) {
    napi_value item;
    Check(env, napi_get_element(env, value, index, &item));
    EncryptedFile file = ReadEncryptedFile(env, item, index);
    std::size_t next_total = 0;
    if (!SafeAdd(total, file.ByteSize(), &next_total)) {
      ThrowTypeError(env, "Encrypted payload is too large.");
    }
    total = next_total;
    files.push_back(std::move(file));
  }

  *byte_size = total;
  return files;
}

std::vector<ChunkedFile> ReadChunkedFiles(napi_env env, napi_value value) {
  bool is_array = false;
  Check(env, napi_is_array(env, value, &is_array));
  if (!is_array) {
    ThrowTypeError(env, "files must be an array.");
  }

  std::uint32_t length = 0;
  Check(env, napi_get_array_length(env, value, &length));
  if (length == 0 || length > 100) {
    ThrowTypeError(env, "files must contain between 1 and 100 entries.");
  }

  std::vector<ChunkedFile> files;
  files.reserve(length);
  for (std::uint32_t index = 0; index < length; ++index) {
    napi_value item;
    Check(env, napi_get_element(env, value, index, &item));

    napi_value id_value;
    napi_value size_value;
    napi_value chunk_count_value;
    Check(env, napi_get_named_property(env, item, "id", &id_value));
    Check(env, napi_get_named_property(env, item, "size", &size_value));
    Check(env,
          napi_get_named_property(env, item, "chunkCount", &chunk_count_value));

    ChunkedFile file;
    file.id = ReadString(env, id_value, "file id");
    file.size = ReadNonNegativeInteger(env, size_value, "file size");
    const auto chunk_count =
        ReadPositiveInteger(env, chunk_count_value, "chunk count");
    const std::uint64_t expected_chunks =
        file.size == 0 ? 1 : ((file.size - 1) / kChunkSizeBytes) + 1;
    if (chunk_count != expected_chunks ||
        chunk_count > std::numeric_limits<std::uint32_t>::max()) {
      ThrowTypeError(env, "chunk count does not match file size.");
    }
    if (file.id.empty() || file.id.size() > 64) {
      ThrowTypeError(env, "file id has an invalid length.");
    }
    for (const auto &existing : files) {
      if (existing.id == file.id) {
        ThrowTypeError(env, "file ids must be unique.");
      }
    }

    file.chunk_count = static_cast<std::uint32_t>(chunk_count);
    file.meta_iv = ReadBase64Property(env, item, "metaIv");
    file.meta_ciphertext = ReadBase64Property(env, item, "metaCiphertext");
    file.chunks.resize(file.chunk_count);
    files.push_back(std::move(file));
  }
  return files;
}

napi_value MakeNumber(napi_env env, double value) {
  napi_value result;
  Check(env, napi_create_double(env, value, &result));
  return result;
}

napi_value MakeUndefined(napi_env env) {
  napi_value result;
  Check(env, napi_get_undefined(env, &result));
  return result;
}

napi_value Render(napi_env env, const StatusResult &result) {
  if (napi_value error = RenderErrorOrNull(env, result); error != nullptr) {
    return error;
  }
  return MakeResult(env, result.status, MakeOkPayload(env));
}

napi_value Render(napi_env env, const UpsertResult &result) {
  if (napi_value error = RenderErrorOrNull(env, result); error != nullptr) {
    return error;
  }
  napi_value payload = MakeOkPayload(env);
  SetProperty(env, payload, "expiresAt",
              MakeNumber(env, static_cast<double>(result.expires_at)));
  SetProperty(env, payload, "files",
              MakeNumber(env, static_cast<double>(result.files)));
  return MakeResult(env, result.status, payload);
}

napi_value Render(napi_env env, TakeResult result) {
  if (napi_value error = RenderErrorOrNull(env, result); error != nullptr) {
    return error;
  }
  napi_value files;
  Check(env, napi_create_array_with_length(env, result.files.size(), &files));
  for (std::size_t index = 0; index < result.files.size(); ++index) {
    Check(env, napi_set_element(env, files, static_cast<std::uint32_t>(index),
                                MakeFilePayload(env, result.files[index])));
  }
  napi_value payload;
  Check(env, napi_create_object(env, &payload));
  SetProperty(env, payload, "files", files);
  napi_value rendered = MakeResult(env, result.status, payload);
  result.files.clear();
  ReleaseUnusedMemory();
  return rendered;
}

napi_value Render(napi_env env, const Stats &stats) {
  napi_value value;
  Check(env, napi_create_object(env, &value));
  SetProperty(env, value, "uploadCount",
              MakeNumber(env, static_cast<double>(stats.upload_count)));
  SetProperty(env, value, "fileCount",
              MakeNumber(env, static_cast<double>(stats.file_count)));
  SetProperty(env, value, "encryptedBytes",
              MakeNumber(env, static_cast<double>(stats.encrypted_bytes)));
  return value;
}

napi_value Render(napi_env env, const CreateChunkedUploadResult &result) {
  if (napi_value error = RenderErrorOrNull(env, result); error != nullptr) {
    return error;
  }
  napi_value payload;
  Check(env, napi_create_object(env, &payload));
  SetProperty(env, payload, "uploadId", MakeString(env, result.upload_id));
  SetProperty(env, payload, "expiresAt",
              MakeNumber(env, static_cast<double>(result.expires_at)));
  SetProperty(env, payload, "chunkSize",
              MakeNumber(env, static_cast<double>(kChunkSizeBytes)));
  return MakeResult(env, result.status, payload);
}

napi_value Render(napi_env env, const CompleteChunkedUploadResult &result) {
  if (napi_value error = RenderErrorOrNull(env, result); error != nullptr) {
    return error;
  }
  napi_value payload = MakeOkPayload(env);
  SetProperty(env, payload, "expiresAt",
              MakeNumber(env, static_cast<double>(result.expires_at)));
  return MakeResult(env, result.status, payload);
}

napi_value Render(napi_env env, const DownloadStatusResult &result) {
  if (napi_value error = RenderErrorOrNull(env, result); error != nullptr) {
    return error;
  }
  napi_value payload = MakeOkPayload(env);
  SetProperty(env, payload, "expiresAt",
              MakeNumber(env, static_cast<double>(result.expires_at)));
  SetProperty(env, payload, "fileCount",
              MakeNumber(env, static_cast<double>(result.file_count)));
  return MakeResult(env, result.status, payload);
}

napi_value Render(napi_env env, const BeginChunkedDownloadResult &result) {
  if (napi_value error = RenderErrorOrNull(env, result); error != nullptr) {
    return error;
  }
  napi_value files;
  Check(env, napi_create_array_with_length(env, result.files->size(), &files));
  for (std::size_t index = 0; index < result.files->size(); ++index) {
    const ChunkedFile &file = (*result.files)[index];
    napi_value item;
    Check(env, napi_create_object(env, &item));
    SetProperty(env, item, "id", MakeString(env, file.id));
    SetProperty(env, item, "size",
                MakeNumber(env, static_cast<double>(file.size)));
    SetProperty(env, item, "chunkCount",
                MakeNumber(env, static_cast<double>(file.chunk_count)));
    SetProperty(env, item, "metaIv", EncodeBase64(env, file.meta_iv));
    SetProperty(env, item, "metaCiphertext",
                EncodeBase64(env, file.meta_ciphertext));
    Check(env, napi_set_element(env, files, static_cast<std::uint32_t>(index),
                                item));
  }

  napi_value payload;
  Check(env, napi_create_object(env, &payload));
  SetProperty(env, payload, "downloadId", MakeString(env, result.download_id));
  SetProperty(env, payload, "downloadToken",
              MakeString(env, result.download_token));
  SetProperty(env, payload, "files", files);
  return MakeResult(env, result.status, payload);
}

napi_value Render(napi_env env, const AcquireChunkResult &result) {
  if (napi_value error = RenderErrorOrNull(env, result); error != nullptr) {
    return error;
  }
  napi_value bytes;
  Check(env, napi_create_external_buffer(
                 env, result.chunk->ciphertext.size(),
                 reinterpret_cast<char *>(result.chunk->ciphertext.data()),
                 NoopExternalBufferFinalizer, nullptr, &bytes));
  napi_value payload;
  Check(env, napi_create_object(env, &payload));
  SetProperty(env, payload, "iv", EncodeBase64(env, result.chunk->iv));
  SetProperty(env, payload, "bytes", bytes);
  return MakeResult(env, result.status, payload);
}

} // namespace drop_server::napi

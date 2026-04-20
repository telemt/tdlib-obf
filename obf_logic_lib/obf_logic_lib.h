#pragma once

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

struct DerivedKeys {
    uint8_t aes_key[32];
    uint8_t mac_key[32];
};

struct BlobResult {
    uint8_t* data;
    size_t len;
    const char* error;
};

DerivedKeys rust_derive_keys(
    const uint8_t* hash_index_seeds, size_t hash_index_seeds_len,
    const uint8_t* session_ticket_seeds, size_t session_ticket_seeds_len,
    const uint8_t* packet_alignment_seeds, size_t packet_alignment_seeds_len,
    const uint8_t* config_cache_seeds, size_t config_cache_seeds_len
);

BlobResult rust_decode_blob(
    const uint8_t* shard_a, size_t shard_a_len,
    const uint8_t* shard_b, size_t shard_b_len,
    const uint8_t* hash_index_seeds, size_t hash_index_seeds_len,
    const uint8_t* session_ticket_seeds, size_t session_ticket_seeds_len,
    const uint8_t* packet_alignment_seeds, size_t packet_alignment_seeds_len,
    const uint8_t* config_cache_seeds, size_t config_cache_seeds_len
);

void rust_free_blob(uint8_t* data, size_t len);

int rust_check_window_entry(
    uint64_t fingerprint,
    const uint8_t* hash_index_seeds, size_t hash_index_seeds_len,
    const uint8_t* session_ticket_seeds, size_t session_ticket_seeds_len,
    const uint8_t* packet_alignment_seeds, size_t packet_alignment_seeds_len,
    const uint8_t* config_cache_seeds, size_t config_cache_seeds_len,
    uint64_t route_window_primary,
    uint64_t route_window_secondary
);

size_t rust_calc_stealth_size(
    size_t data_size,
    size_t enc_header_size,
    size_t raw_header_size,
    size_t min_padding,
    size_t max_padding
);

uint8_t* rust_sha256(const uint8_t* data, size_t len);
void rust_sha256_free(uint8_t* hash);

uint8_t* rust_generate_x25519_public_key(const uint8_t* seed);
void rust_generate_x25519_public_key_free(uint8_t* key);
uint8_t* rust_generate_secp256r1_public_key(const uint8_t* seed);
void rust_generate_secp256r1_public_key_free(uint8_t* key);

void rust_hmac_sha256_finalize(
    const uint8_t* secret,
    const uint8_t* data,
    size_t data_len,
    int32_t unix_time,
    uint8_t* dest
);

uint8_t* rust_init_grease_values(const uint8_t* seed, size_t seed_len, size_t* result_len);
void rust_grease_values_free(uint8_t* data, size_t len);

struct ExecutorConfig {
    size_t grease_value_count;
    bool has_ech;
    uint8_t ech_outer_type;
    uint16_t ech_kdf_id;
    uint16_t ech_aead_id;
    int32_t ech_payload_length;
    int32_t ech_enc_key_length;
    uint16_t alps_type;
    int32_t padding_target_entropy;
    uint16_t pq_group_id_override;
    size_t padding_extension_payload_length_override;
    bool force_http11_only_alpn;
};

uint8_t* rust_client_hello_execute(
    const uint8_t* domain, size_t domain_len,
    const uint8_t* secret,
    int32_t unix_time,
    ExecutorConfig config,
    const uint8_t* rng_seed, size_t rng_seed_len,
    size_t* result_len
);
void rust_client_hello_free(uint8_t* data, size_t len);

#ifdef __cplusplus
}

namespace td {
namespace mtproto {

using ::BlobResult;
using ::DerivedKeys;
using ::ExecutorConfig;

class ObfuscationLib {
public:
    static DerivedKeys derive_keys(
        const std::string& hash_index_seeds,
        const std::string& session_ticket_seeds,
        const std::string& packet_alignment_seeds,
        const std::string& config_cache_seeds
    ) {
        return rust_derive_keys(
            reinterpret_cast<const uint8_t*>(hash_index_seeds.data()), hash_index_seeds.size(),
            reinterpret_cast<const uint8_t*>(session_ticket_seeds.data()), session_ticket_seeds.size(),
            reinterpret_cast<const uint8_t*>(packet_alignment_seeds.data()), packet_alignment_seeds.size(),
            reinterpret_cast<const uint8_t*>(config_cache_seeds.data()), config_cache_seeds.size()
        );
    }

    static std::string decode_blob(
        const std::string& shard_a,
        const std::string& shard_b,
        const std::string& hash_index_seeds,
        const std::string& session_ticket_seeds,
        const std::string& packet_alignment_seeds,
        const std::string& config_cache_seeds
    ) {
        BlobResult result = rust_decode_blob(
            reinterpret_cast<const uint8_t*>(shard_a.data()), shard_a.size(),
            reinterpret_cast<const uint8_t*>(shard_b.data()), shard_b.size(),
            reinterpret_cast<const uint8_t*>(hash_index_seeds.data()), hash_index_seeds.size(),
            reinterpret_cast<const uint8_t*>(session_ticket_seeds.data()), session_ticket_seeds.size(),
            reinterpret_cast<const uint8_t*>(packet_alignment_seeds.data()), packet_alignment_seeds.size(),
            reinterpret_cast<const uint8_t*>(config_cache_seeds.data()), config_cache_seeds.size()
        );

        if (result.error != nullptr) {
            throw std::runtime_error(result.error);
        }

        std::string decoded(reinterpret_cast<char*>(result.data), result.len);
        rust_free_blob(result.data, result.len);
        return decoded;
    }

    static bool check_window_entry(
        uint64_t fingerprint,
        const std::string& hash_index_seeds,
        const std::string& session_ticket_seeds,
        const std::string& packet_alignment_seeds,
        const std::string& config_cache_seeds,
        uint64_t route_window_primary,
        uint64_t route_window_secondary
    ) {
        return rust_check_window_entry(
            fingerprint,
            reinterpret_cast<const uint8_t*>(hash_index_seeds.data()), hash_index_seeds.size(),
            reinterpret_cast<const uint8_t*>(session_ticket_seeds.data()), session_ticket_seeds.size(),
            reinterpret_cast<const uint8_t*>(packet_alignment_seeds.data()), packet_alignment_seeds.size(),
            reinterpret_cast<const uint8_t*>(config_cache_seeds.data()), config_cache_seeds.size(),
            route_window_primary,
            route_window_secondary
        ) == 0;
    }

    static size_t calc_stealth_size(
        size_t data_size,
        size_t enc_header_size,
        size_t raw_header_size,
        size_t min_padding = 0,
        size_t max_padding = 0
    ) {
        return rust_calc_stealth_size(data_size, enc_header_size, raw_header_size, min_padding, max_padding);
    }

    static std::string sha256(const std::string& data) {
        uint8_t* hash = rust_sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        if (hash == nullptr) {
            throw std::runtime_error("SHA-256 calculation failed");
        }
        std::string result(reinterpret_cast<char*>(hash), 32);
        rust_sha256_free(hash);
        return result;
    }

    static std::string generate_x25519_public_key(const std::string& seed) {
        if (seed.size() != 32) {
            throw std::runtime_error("X25519 seed must be exactly 32 bytes");
        }
        uint8_t* key = rust_generate_x25519_public_key(reinterpret_cast<const uint8_t*>(seed.data()));
        if (key == nullptr) {
            throw std::runtime_error("X25519 public key generation failed");
        }
        std::string result(reinterpret_cast<char*>(key), 32);
        rust_generate_x25519_public_key_free(key);
        return result;
    }

    static std::string generate_secp256r1_public_key(const std::string& seed) {
        if (seed.size() != 32) {
            throw std::runtime_error("secp256r1 seed must be exactly 32 bytes");
        }
        uint8_t* key = rust_generate_secp256r1_public_key(reinterpret_cast<const uint8_t*>(seed.data()));
        if (key == nullptr) {
            throw std::runtime_error("secp256r1 public key generation failed");
        }
        std::string result(reinterpret_cast<char*>(key), 65);
        rust_generate_secp256r1_public_key_free(key);
        return result;
    }

    static void hmac_sha256_finalize(const std::string& secret, const std::string& data, int32_t unix_time, std::string& dest) {
        dest.resize(32);
        rust_hmac_sha256_finalize(
            reinterpret_cast<const uint8_t*>(secret.data()),
            reinterpret_cast<const uint8_t*>(data.data()),
            data.size(),
            unix_time,
            reinterpret_cast<uint8_t*>(dest.data())
        );
    }

    static std::string init_grease_values(const std::string& seed) {
        size_t result_len = 0;
        uint8_t* vec = rust_init_grease_values(reinterpret_cast<const uint8_t*>(seed.data()), seed.size(), &result_len);
        if (vec == nullptr) {
            if (result_len == 0) {
                return std::string();
            }
            throw std::runtime_error("GREASE initialization failed");
        }
        std::string result(reinterpret_cast<char*>(vec), result_len);
        rust_grease_values_free(vec, result_len);
        return result;
    }

    static std::string execute_client_hello(
        const std::string& domain,
        const std::string& secret,
        int32_t unix_time,
        ExecutorConfig config,
        const std::string& rng_seed
    ) {
        size_t result_len = 0;
        uint8_t* data = rust_client_hello_execute(
            reinterpret_cast<const uint8_t*>(domain.data()), domain.size(),
            reinterpret_cast<const uint8_t*>(secret.data()),
            unix_time,
            config,
            reinterpret_cast<const uint8_t*>(rng_seed.data()), rng_seed.size(),
            &result_len
        );
        if (data == nullptr) {
            throw std::runtime_error("ClientHello execution failed");
        }
        std::string result(reinterpret_cast<char*>(data), result_len);
        rust_client_hello_free(data, result_len);
        return result;
    }
};

class ClientHelloExecutor {
public:
    static std::string execute(
        const std::string& domain,
        const std::string& secret,
        int32_t unix_time,
        ExecutorConfig config,
        const std::string& rng_seed
    ) {
        return ObfuscationLib::execute_client_hello(domain, secret, unix_time, config, rng_seed);
    }
};

} // namespace mtproto
} // namespace td

#endif

// SPDX-FileCopyrightText: Copyright 2026 telemt community
// SPDX-License-Identifier: MIT

#include "td/mtproto/BlobStore.h"

#include "td/telegram/ConfigManager.h"
#include "td/telegram/ReferenceTable.h"

#include "td/utils/tests.h"

#include "test/stealth/SourceContractFileReader.h"

#include <string_view>

namespace aux_decode_sink_source_contract {

static td::string extract_region(std::string_view source, td::Slice begin_marker, td::Slice end_marker) {
  auto begin = source.find(begin_marker.str());
  CHECK(begin != td::string::npos);
  auto end = source.find(end_marker.str(), begin + begin_marker.size());
  CHECK(end != td::string::npos);
  CHECK(end > begin);
  return td::string(source.substr(begin, end - begin));
}

TEST(AuxDecodeSinkSourceContract, DecodeConfigTouchesRetainedBlockBeforeReviewedAuxiliaryLoad) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");
  auto region = extract_region(source, "Result<SimpleConfig> decode_config(Slice input) {",
                               "Result<SimpleConfig> decode_simple_config_payload(Slice payload) {");

  auto touch_pos = region.find("touch_catalog_auxiliary_block();");
  auto load_pos = region.find("BlobStore::load(mtproto::BlobRole::Auxiliary)");

  ASSERT_TRUE(touch_pos != td::string::npos);
  ASSERT_TRUE(load_pos != td::string::npos);
  ASSERT_TRUE(touch_pos < load_pos);
}

TEST(AuxDecodeSinkSourceContract, DecodeConfigChecksReviewedAuxFingerprintBeforeLengthGateAndDecrypt) {
  auto source = td::mtproto::test::read_repo_text_file("td/telegram/ConfigManager.cpp");
  auto region = extract_region(source, "Result<SimpleConfig> decode_config(Slice input) {",
                               "Result<SimpleConfig> decode_simple_config_payload(Slice payload) {");

  auto check_pos = region.find("TRY_STATUS(check_config_entry(rsa.get_fingerprint()));");
  auto length_pos = region.find("if (input.size() < 344 || input.size() > 1024) {");
  auto decrypt_pos = region.find("rsa.decrypt_signature(data_rsa_slice, data_rsa_slice);");

  ASSERT_TRUE(check_pos != td::string::npos);
  ASSERT_TRUE(length_pos != td::string::npos);
  ASSERT_TRUE(decrypt_pos != td::string::npos);
  ASSERT_TRUE(check_pos < length_pos);
  ASSERT_TRUE(length_pos < decrypt_pos);
}

TEST(AuxDecodeSinkSourceContract, CheckConfigEntryAcceptsOnlyReviewedAuxiliarySlot) {
  using td::mtproto::BlobRole;

  ASSERT_TRUE(td::check_config_entry(td::ReferenceTable::slot_value(BlobRole::Auxiliary)).is_ok());
  ASSERT_TRUE(td::check_config_entry(td::ReferenceTable::slot_value(BlobRole::Primary)).is_error());
  ASSERT_TRUE(td::check_config_entry(td::ReferenceTable::slot_value(BlobRole::Secondary)).is_error());
}

}  // namespace aux_decode_sink_source_contract
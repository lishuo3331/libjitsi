#include "reedsolomon.hpp"

#include <cstring>

namespace xfec {

std::vector<JNINativeMethod> ReedSolomon::methods() {
  return {
      Jmethod(encode, ReedSolomon::encode),
      Jmethod(decode, ReedSolomon::decode),
  };
}

jbyteArray ReedSolomon::encode(
    JavaClass::Jenv &env,
    jint sourceSymbols,
    jint repairSymbols,
    jint symbolLength,
    jobjectArray shards) {
  of_session_t *session = nullptr;
  auto status = of_create_codec_instance(
      &session, OF_CODEC_REED_SOLOMON_GF_2_8_STABLE, OF_ENCODER, 0);
  std::shared_ptr<of_session_t> guard(session, of_release_codec_instance);
  if (status != OF_STATUS_OK) {
    return raise(env, 0, "Failed to create codec");
  }
  auto count = env.size(shards);
  if (count != sourceSymbols + repairSymbols) {
    return raise(env, 0, "Incorrect number of shards");
  }
  assert(count == sourceSymbols + repairSymbols);
  std::vector<void *> pointers(count, nullptr);
  for (auto i = 0; i < count; ++i) {
    auto shard = (jbyteArray) env->GetObjectArrayElement(env.env, shards, i);
    if (shard == nullptr) {
      return raise(env, 0, "Invalid data");
    }
    if (env.size(shard) != symbolLength) {
      return raise(env, 0, "Incorrect size of source shard");
    }
    pointers[i] = env.array(shard, i >= sourceSymbols);
  }
  of_parameters_t parameters;
  parameters.nb_source_symbols = sourceSymbols;
  parameters.nb_repair_symbols = repairSymbols;
  parameters.encoding_symbol_length = symbolLength;
  status = of_set_fec_parameters(session, &parameters);
  if (status != OF_STATUS_OK) {
    return raise(env, 0, "Failed to set fec parameters");
  }
  for (auto i = sourceSymbols; i < count; ++i) {
    status = of_build_repair_symbol(session, pointers.data(), i);
    if (status != OF_STATUS_OK) {
      return raise(env, 0, "Failed to build repair symbol");
    }
  }
  return nullptr;
}

jbyteArray ReedSolomon::decode(
    JavaClass::Jenv &env,
    jint sourceSymbols,
    jint repairSymbols,
    jint symbolLength,
    jobjectArray shards) {
  of_session_t *session = nullptr;
  auto status = of_create_codec_instance(
      &session, OF_CODEC_REED_SOLOMON_GF_2_8_STABLE, OF_DECODER, 0);
  std::shared_ptr<of_session_t> guard(session, of_release_codec_instance);
  if (status != OF_STATUS_OK) {
    return raise(env, 0, "Failed to create codec");
  }
  auto count = env.size(shards);
  if (count != sourceSymbols + repairSymbols) {
    return raise(env, 0, "Incorrect number of shards");
  }
  assert(count == sourceSymbols + repairSymbols);
  std::vector<void *> pointers(count, nullptr);
  size_t symbolCount = 0;
  size_t missingCount = 0;
  for (auto i = 0; i < count; ++i) {
    auto shard = (jbyteArray) env->GetObjectArrayElement(env.env, shards, i);
    if (shard == nullptr) {
      missingCount += i < sourceSymbols;
      continue;
    }
    ++symbolCount;
    pointers[i] = env.array(shard, false);
  }
  if (symbolCount < sourceSymbols) {
    return raise(env, 0, "Need more shards");
  }
  if (missingCount == 0) {
    return nullptr;
  }
  of_parameters_t parameters;
  parameters.nb_source_symbols = sourceSymbols;
  parameters.nb_repair_symbols = repairSymbols;
  parameters.encoding_symbol_length = symbolLength;
  status = of_set_fec_parameters(session, &parameters);
  if (status != OF_STATUS_OK) {
    return raise(env, 0, "Failed to set fec parameters");
  }
  status = of_set_available_symbols(session, pointers.data());
  if (status != OF_STATUS_OK) {
    return raise(env, 0, "Failed to set available symbols");
  }
  status = of_finish_decoding(session);
  if (status != OF_STATUS_OK) {
    return raise(env, 0, "Failed to finish decoding");
  }
  status = of_get_source_symbols_tab(session, pointers.data());
  if (status != OF_STATUS_OK) {
    return raise(env, 0, "Failed to get source symbols");
  }
  for (auto i = 0; i < sourceSymbols; ++i) {
    auto shard = (jbyteArray) env->GetObjectArrayElement(env.env, shards, i);
    if (shard == nullptr) {
      auto repair = env->NewByteArray(env.env, symbolLength);
      env->SetByteArrayRegion(
          env.env, repair, 0, symbolLength, (jbyte *) pointers[i]);
      env->SetObjectArrayElement(env.env, shards, i, repair);
      free(pointers[i]);
    }
  }
  return nullptr;
}

void ReedSolomon::load(JavaVM *jvm, JNIEnv *env, std::string package) {
  JavaClass::load<ReedSolomon>(jvm, env, package + "/xfec/ReedSolomon$Native");
}

void ReedSolomon::unload(JavaVM *jvm, JNIEnv *env) {
  JavaClass::unload<ReedSolomon>(jvm, env);
}

} // namespace xfec

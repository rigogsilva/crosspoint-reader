#include "AutomaticProgressCheck.h"

#include <Logging.h>
#include <WiFi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <algorithm>

#include "AutomaticWifiConnectionPolicy.h"
#include "KOReaderCredentialStore.h"
#include "KOReaderDocumentId.h"
#include "WifiCredentialStore.h"

namespace {

// Association only. The radio is brought up by start() on the main loop task:
// WiFi.mode() blocks forever when called from a secondary task, and every other
// WiFi bring-up in this codebase runs on the main task for the same reason.
// Polls stopRequested so a destructing owner can reclaim the task promptly.
bool connectHeadless(const std::atomic<bool>& stopRequested) {
  if (WiFi.status() == WL_CONNECTED) return true;

  const uint32_t deadline = millis() + AutomaticWifiConnectionPolicy::BACKGROUND_TIMEOUT_MS;

  for (size_t i = 0; i < WIFI_STORE.getCredentialCount(); i++) {
    const auto cred = WIFI_STORE.getCredentialAt(i);
    if (!cred) continue;

    const int32_t remaining = static_cast<int32_t>(deadline - millis());
    if (remaining <= 0) break;

    LOG_DBG("KOSync", "Automatic check: trying saved network %s", cred->ssid.c_str());
    if (cred->password.empty()) {
      WiFi.begin(cred->ssid.c_str());
    } else {
      WiFi.begin(cred->ssid.c_str(), cred->password.c_str());
    }

    const uint32_t attemptTimeoutMs = std::min<uint32_t>(static_cast<uint32_t>(remaining),
                                                         AutomaticWifiConnectionPolicy::FALLBACK_ATTEMPT_TIMEOUT_MS);
    const uint32_t attemptStartedAt = millis();
    while (millis() - attemptStartedAt < attemptTimeoutMs) {
      if (stopRequested.load(std::memory_order_acquire)) return false;
      if (WiFi.status() == WL_CONNECTED) {
        LOG_DBG("KOSync", "Automatic check: connected to %s", cred->ssid.c_str());
        return true;
      }
      vTaskDelay(pdMS_TO_TICKS(100));
    }
    WiFi.disconnect();
  }
  return WiFi.status() == WL_CONNECTED;
}

}  // namespace

AutomaticProgressCheck::~AutomaticProgressCheck() {
  stopRequested_.store(true, std::memory_order_release);

  // Never vTaskDelete() here. The task may hold storageMutex (loadFromFile) or
  // be inside a wolfSSL handshake; killing it there strands the mutex and every
  // subsequent SD access blocks on it forever, freezing the device.
  const TickType_t startedAt = xTaskGetTickCount();
  while (!taskExited_.load(std::memory_order_acquire) &&
         (xTaskGetTickCount() - startedAt) < pdMS_TO_TICKS(TASK_JOIN_TIMEOUT_MS)) {
    vTaskDelay(pdMS_TO_TICKS(10));
  }

  if (!taskExited_.load(std::memory_order_acquire)) {
    // Leaking the task is still better than a stranded storage mutex.
    LOG_ERR("KOSync", "Automatic check task did not exit within %u ms", TASK_JOIN_TIMEOUT_MS);
  }
  taskHandle_ = nullptr;
}

bool AutomaticProgressCheck::start(const std::string& epubPath) {
  if (isRunning()) return false;
  if (!KOREADER_STORE.hasCredentials()) return false;

  epubPath_ = epubPath;
  remoteProgress_ = {};
  error_ = KOReaderSyncClient::OK;
  stopRequested_.store(false, std::memory_order_release);
  taskExited_.store(false, std::memory_order_release);

  // Bring the radio up here, on the main loop task. WiFi.mode() never returns
  // when called from a secondary task, which hung the reader on book open.
  WiFi.persistent(false);  // Credentials are managed by WifiCredentialStore
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true, true);  // Abort any SDK auto-connect and clear NVS SSID

  status_.store(Status::RUNNING, std::memory_order_release);

  if (xTaskCreatePinnedToCore(&taskTrampoline, "AutoProgressCheck", 8192, this, 1, &taskHandle_, 0) != pdPASS) {
    LOG_ERR("KOSync", "Failed to create automatic progress check task");
    taskExited_.store(true, std::memory_order_release);
    status_.store(Status::DONE_ERROR, std::memory_order_release);
    error_ = KOReaderSyncClient::NETWORK_ERROR;
    taskHandle_ = nullptr;
    return false;
  }
  return true;
}

void AutomaticProgressCheck::taskTrampoline(void* arg) {
  auto* self = static_cast<AutomaticProgressCheck*>(arg);
  self->run();
  self->taskExited_.store(true, std::memory_order_release);
  vTaskDelete(nullptr);  // never touches self after this point
}

void AutomaticProgressCheck::run() {
  // Load saved WiFi credentials from SD before the headless connect attempt.
  // (WifiSelectionActivity does this in onEnter(); a background check runs
  // without that activity, so it must load them itself.)
  WIFI_STORE.loadFromFile();

  if (stopRequested_.load(std::memory_order_acquire)) {
    status_.store(Status::DONE_ERROR, std::memory_order_release);
    return;
  }

  if (!connectHeadless(stopRequested_)) {
    LOG_DBG("KOSync", "Automatic check: WiFi unavailable");
    error_ = KOReaderSyncClient::NETWORK_ERROR;
    status_.store(Status::DONE_ERROR, std::memory_order_release);
    return;
  }

  const std::string hash = KOREADER_STORE.getMatchMethod() == DocumentMatchMethod::FILENAME
                               ? KOReaderDocumentId::calculateFromFilename(epubPath_)
                               : KOReaderDocumentId::calculate(epubPath_);
  if (hash.empty()) {
    LOG_ERR("KOSync", "Automatic check: document hash failed");
    error_ = KOReaderSyncClient::NETWORK_ERROR;
    status_.store(Status::DONE_ERROR, std::memory_order_release);
    return;
  }

  KOReaderProgress progress;
  const auto result =
      KOReaderSyncClient::getProgress(hash, progress, KOReaderSyncClient::DEFAULT_REQUEST_TIMEOUT_MS,
                                      [this] { return stopRequested_.load(std::memory_order_acquire); });
  error_ = result;

  // Drop the radio; the reader resumes normal low-power operation.
  WiFi.disconnect(true, false);

  if (result == KOReaderSyncClient::OK) {
    remoteProgress_ = std::move(progress);
    status_.store(Status::DONE_OK, std::memory_order_release);
  } else if (result == KOReaderSyncClient::NOT_FOUND) {
    status_.store(Status::DONE_NOT_FOUND, std::memory_order_release);
  } else {
    LOG_DBG("KOSync", "Automatic check: getProgress failed (%d)", static_cast<int>(result));
    status_.store(Status::DONE_ERROR, std::memory_order_release);
  }
}

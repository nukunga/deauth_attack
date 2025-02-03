#pragma once
#include <string>
#include <csignal>

// Deauthentication Attack 함수 선언
void runDeauthAttack(const std::string& dev, const std::string& apMac, const std::string& stationMac, bool broadcastMode, volatile sig_atomic_t* keep_running);

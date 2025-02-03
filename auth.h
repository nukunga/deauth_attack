#pragma once
#include <string>
#include <csignal>

// Authentication Attack 함수 선언
void runAuthAttack(const std::string& dev, const std::string& apMac, const std::string& stationMac, volatile sig_atomic_t* keep_running); 
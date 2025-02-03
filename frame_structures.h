#pragma once
#include <string>
#include <cstdint>
#include <vector>

// 설정값
const int PACKET_INTERVAL_MS = 100;  // 패킷 전송 간격 (밀리초)

// 802.11 / Radiotap 구조체
#pragma pack(push, 1)
struct RadiotapHeader {
    uint8_t  it_version;
    uint8_t  it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((packed));
#pragma pack(pop)

#pragma pack(push, 1)
struct IEEE80211Header {
    uint16_t frameControl;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seqCtrl;
};

// Authentication 프레임 바디
struct AuthFrameBody {
    uint16_t authAlgorithm;
    uint16_t authSeq;
    uint16_t statusCode;
} __attribute__((packed));

// Deauthentication 프레임 바디
struct DeauthFrameBody {
    uint16_t reasonCode;
} __attribute__((packed));
#pragma pack(pop)

// 상수 정의
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint16_t DEFAULT_REASON_CODE = 0x0007;  // Class 3 frame received from nonassociated STA
const uint16_t DEFAULT_AUTH_ALGORITHM = 0x0000;  // Open System authentication
const uint16_t DEFAULT_STATUS_CODE = 0x0000;     // Successful

// MAC 주소 변환 함수
inline bool macStringToBytes(const std::string& mac, uint8_t* bytes) {
    unsigned int values[6];
    if (sscanf(mac.c_str(), "%x:%x:%x:%x:%x:%x", 
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return false;
    }
    for(int i = 0; i < 6; i++) {
        bytes[i] = static_cast<uint8_t>(values[i]);
    }
    return true;
}
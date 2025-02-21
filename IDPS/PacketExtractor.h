#pragma once

#include "DriverCommunicator.h"
#include <cstdint>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

constexpr uint8_t MAX_PACKET_COUNT = 100;

class PacketExtractor final
{
private:
    std::mutex m_queueMutex;
    std::queue<std::vector<uint8_t>> m_packetQueue;
    std::thread m_extractorThread;
    HANDLE m_hFile;

    // Main private methods
    PacketExtractor();
    void threadRoutine();

    // Helper methods
    void openPacketFile();
    void readFromFile(void* outBuffer, uint16_t numBytes);
    void truncatePacketFile();

public:
    // Singleton methods
    ~PacketExtractor() noexcept;
    static PacketExtractor& getInstance() noexcept;
    PacketExtractor(const PacketExtractor& other) = delete;
    void operator=(const PacketExtractor& other) = delete;

    // methods
    std::vector<uint8_t> getPacket() noexcept;
};


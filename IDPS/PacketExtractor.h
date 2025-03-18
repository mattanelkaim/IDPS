#pragma once

#include "Windows.h"
#include <cstdint>
#include <exception>
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
    std::exception_ptr& m_outException;
    HANDLE m_hFile;

    // Main private methods
    explicit PacketExtractor(std::exception_ptr& outException);
    void threadRoutine();

    // Helper methods
    void openPacketFile();
    void readFromFile(void* outBuffer, uint16_t numBytes);
    void truncatePacketFile();

public:
    // Singleton methods
    ~PacketExtractor() noexcept;
    static PacketExtractor& getInstance(std::exception_ptr& outException);
    PacketExtractor(const PacketExtractor& other) = delete;
    void operator=(const PacketExtractor& other) = delete;

    // Methods
    std::vector<uint8_t> getPacket();
};


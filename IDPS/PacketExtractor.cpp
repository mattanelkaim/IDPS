#include "DriverCommunicator.h"
#include "IDPSExceptions.hpp"
#include "PacketExtractor.h"

PacketExtractor::PacketExtractor(std::exception_ptr& outException) :
    m_extractorThread(&PacketExtractor::threadRoutine, this),
    m_outException(outException),
    m_hFile(INVALID_HANDLE_VALUE)
{
    this->m_extractorThread.detach(); // letting packet extractor thread work in the background
}

void PacketExtractor::threadRoutine()
{
    // Opening the packet file
    this->openPacketFile();

    try
    {
        uint8_t packetCounter = 0;
        uint16_t packetSize = 0;
        std::vector<uint8_t> rawPacket;

        while (true)
        {
            // Truncating the file every MAX_PACKET_COUNT'th packet read
            if (packetCounter == MAX_PACKET_COUNT)
            {
                //this->truncatePacketFile();
                packetCounter = 0;
            }

            // Reading packet size and data
            readFromFile(&packetSize, sizeof(packetSize));
            rawPacket.resize(packetSize);
            readFromFile(rawPacket.data(), packetSize);
            ++packetCounter;

            // Pushing the new packet into the queue
            std::lock_guard lg(m_queueMutex);
            this->m_packetQueue.push(rawPacket);
        }
    }
    catch (...)
    {
        this->m_outException = std::current_exception();
        // Pushing dummy packet into the queue
        std::lock_guard lg(m_queueMutex);
        this->m_packetQueue.emplace();
    }
}

std::vector<uint8_t> PacketExtractor::getPacket()
{
    // Waiting for a packet to arrive (in practice shouldn't happen often)
    while (this->m_packetQueue.empty()) { std::this_thread::yield(); }

    // Extracting the packet
    std::lock_guard lg(m_queueMutex);
    std::vector<uint8_t> toReturn = this->m_packetQueue.front();
    this->m_packetQueue.pop();

    return toReturn;
}


// HELPER FUNCTIONS

void PacketExtractor::openPacketFile()
{
    // Opening (or creating) the file with FILE_SHARE_WRITE to allow the driver
    // to write data to the file simultaneous to the IDPS reading from it
    this->m_hFile = CreateFileW(PACKET_FILE_PATH, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == m_hFile)
        throw FatalWinException("Failed to open packet file.", GetLastError());
}

void PacketExtractor::readFromFile(void* outBuffer, uint16_t numBytes) const
{
    DWORD bytesRead = 0;
    DWORD bytesLeft = numBytes;

    // Continuously reading from the file until the desired number of bytes is reached
    while (bytesLeft)
    {
        if (!ReadFile(this->m_hFile, outBuffer, bytesLeft, &bytesRead, NULL))
            throw FatalWinException("Failed to read from packet file.", GetLastError());
        bytesLeft -= bytesRead;
    }
}

void PacketExtractor::truncatePacketFile() const
{
    DriverCommunicator::getInstance().truncateFile();

    // Reseting the file pointer
    if (!SetFilePointerEx(this->m_hFile, {{0}}, NULL, FILE_BEGIN))
        throw FatalWinException("Failed to set packet file pointer.", GetLastError());
}

PacketExtractor::~PacketExtractor() noexcept
{
    // No need to validate handle - behavior is defined for INVALID_HANDLE_VALUE
    CloseHandle(this->m_hFile);
}

// SINGLETON METHODS

PacketExtractor& PacketExtractor::getInstance(std::exception_ptr& outException)
{
    static PacketExtractor instance(outException);
    return instance;
}

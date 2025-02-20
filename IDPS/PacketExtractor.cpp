#include "PacketExtractor.h"
#include "DriverCommunicator.h"

PacketExtractor::PacketExtractor() : m_extractorThread(&PacketExtractor::threadRoutine, this), 
                                     m_queueMutex(),
                                     m_hFile(INVALID_HANDLE_VALUE),
                                     m_packetQueue()
{
    this->m_extractorThread.detach(); // letting packet extractor thread work in the background
}

void PacketExtractor::threadRoutine()
{
    uint8_t packetsRead = 0;
    uint16_t packetSize = 0;
    std::vector<uint8_t> rawPacket;
    bool pending = false;

    while (true)
    {
        // Truncating the file every 100'th packet read
        if (packetsRead == 100)
        {
            this->truncatePacketFile();
            packetsRead = 0;
        }

        // Reading packet size and data
        readFromFile(&packetSize, sizeof(packetSize));
        rawPacket.resize(packetSize);
        readFromFile(rawPacket.data(), packetSize);
        packetsRead++;

        // Pushing the new packet into the queue
        this->m_queueMutex.lock();
        this->m_packetQueue.push(rawPacket);
        this->m_queueMutex.unlock();
    }
}

std::vector<uint8_t> PacketExtractor::getPacket() noexcept
{
    // loading new packet
    while (this->m_packetQueue.empty()); { (void)0; }
    this->m_queueMutex.lock();
    const std::vector<uint8_t> toReturn = std::move(this->m_packetQueue.front()); // Move a reference instead of copying
    this->m_packetQueue.pop();
    this->m_queueMutex.unlock();

    return toReturn;
}


// HELPER FUNCTIONS

void PacketExtractor::openPacketFile()
{
    /* opening (or creating) the file with FILE_SHARE_WRITE to allow the driver to write data to the file
       simultaneouse to the IDPS reading from it */
    this->m_hFile = CreateFileW(L"C:\\Users\\nick_\\Desktop\\VMShared\\packetFlow.bin", GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == m_hFile)
        throw std::runtime_error("Failed to open packet file.");
}

void PacketExtractor::readFromFile(void* outBuffer, uint16_t numBytes)
{
    DWORD bytesRead = 0;
    DWORD bytesLeft = numBytes;

    // Continuously reading from the file until the desired number of bytes is reached
    while (bytesLeft)
    {
        if (!ReadFile(this->m_hFile, outBuffer, bytesLeft, &bytesRead, NULL))
            throw std::runtime_error("Failed to read from packet file.");
        bytesLeft -= bytesRead;
    }
}

void PacketExtractor::truncatePacketFile()
{
    DriverCommunicator::getInstance().truncateFile();

    // Reseting the file pointer
    if (!SetFilePointerEx(this->m_hFile, {0}, NULL, FILE_BEGIN))
        throw std::runtime_error("Failed to set packet file pointer.");
}

PacketExtractor::~PacketExtractor() noexcept
{
    // No need to validate handle - behavior is defined for INVALID_HANDLE_VALUE
    CloseHandle(this->m_hFile);
}

// SINGLETON METHODS

PacketExtractor& PacketExtractor::getInstance() noexcept
{
    static PacketExtractor instance;
    return instance;
}

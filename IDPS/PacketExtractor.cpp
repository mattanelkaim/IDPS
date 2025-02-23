#include "PacketExtractor.h"
#include "IDPSExceptions.hpp"

PacketExtractor::PacketExtractor(std::exception_ptr& outException) : m_extractorThread(&PacketExtractor::threadRoutine, this),
                                     m_queueMutex(),
                                     m_hFile(INVALID_HANDLE_VALUE),
                                                                     m_packetQueue(),
                                                                     m_outException(outException)
{
    this->m_extractorThread.detach(); // letting packet extractor thread work in the background
}

void PacketExtractor::threadRoutine()
{
    uint8_t packetCounter = 0;
    uint16_t packetSize = 0;
    std::vector<uint8_t> rawPacket;
    bool pending = false;

    // Opening the packet file
    this->openPacketFile();

    try
    {
    while (true)
    {
        // Truncating the file every MAX_PACKET_COUNT'th packet read
        if (packetCounter == MAX_PACKET_COUNT)
        {
            this->truncatePacketFile();
            packetCounter = 0;
        }

        // Reading packet size and data
        readFromFile(&packetSize, sizeof(packetSize));
        rawPacket.resize(packetSize);
        readFromFile(rawPacket.data(), packetSize);
        packetCounter++;

        // Pushing the new packet into the queue
        this->m_queueMutex.lock();
        this->m_packetQueue.push(rawPacket);
        this->m_queueMutex.unlock();
    }
}
    catch (...)
    {
        // Pushing dummy packet into the queue
        this->m_queueMutex.lock();
        this->m_packetQueue.push({});
        this->m_queueMutex.unlock();
        this->m_outException = std::current_exception();
    }
}

std::vector<uint8_t> PacketExtractor::getPacket() noexcept
{
    // loading new packet
    while (this->m_packetQueue.empty()); { (void)0; }
    this->m_queueMutex.lock();
    std::vector<uint8_t> toReturn = std::move(this->m_packetQueue.front()); // Move a reference instead of copying
    this->m_packetQueue.pop();
    this->m_queueMutex.unlock();

    return toReturn;
}


// HELPER FUNCTIONS

void PacketExtractor::openPacketFile()
{
    /* opening (or creating) the file with FILE_SHARE_WRITE to allow the driver to write data to the file
       simultaneouse to the IDPS reading from it */
    this->m_hFile = CreateFileW(PACKET_FILE_PATH, GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == m_hFile)
        throw FatalException("Failed to open packet file.");
}

void PacketExtractor::readFromFile(void* outBuffer, uint16_t numBytes)
{
    DWORD bytesRead = 0;
    DWORD bytesLeft = numBytes;

    // Continuously reading from the file until the desired number of bytes is reached
    while (bytesLeft)
    {
        if (!ReadFile(this->m_hFile, outBuffer, bytesLeft, &bytesRead, NULL))
            throw FatalException("Failed to read from packet file.");
        bytesLeft -= bytesRead;
    }
}

void PacketExtractor::truncatePacketFile()
{
    DriverCommunicator::getInstance().truncateFile();

    // Reseting the file pointer
    if (!SetFilePointerEx(this->m_hFile, {0}, NULL, FILE_BEGIN))
        throw FatalException("Failed to set packet file pointer.");
}

PacketExtractor::~PacketExtractor() noexcept
{
    // No need to validate handle - behavior is defined for INVALID_HANDLE_VALUE
    CloseHandle(this->m_hFile);
}

// SINGLETON METHODS

PacketExtractor& PacketExtractor::getInstance(std::exception_ptr& outException) noexcept
{
    static PacketExtractor instance(outException);
    return instance;
}

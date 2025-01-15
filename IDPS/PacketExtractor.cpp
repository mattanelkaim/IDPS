#include "PacketExtractor.h"
#include <fstream>


PacketExtractor::PacketExtractor() : m_extractorThread(&PacketExtractor::threadRoutine, this)
{
    this->m_extractorThread.detach(); // letting packet extractor thread work in the background

    // obtaining a device handle to the driver
    this->m_deviceHandle = CreateFileW(L"\\\\.\\SnifferDeviceLink", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
    if (this->m_deviceHandle == INVALID_HANDLE_VALUE)
        throw std::runtime_error("Please run the driver prior to running the IDPS.");
}


void PacketExtractor::threadRoutine()
{
    std::ifstream packetFile(PACKET_FILE_PATH, std::ios::binary);
    if (!packetFile.is_open())
        throw std::runtime_error("Error opening packet file.");

    uint16_t packetSize = 0;
    std::vector<char> rawPacket;
    bool pending = false;

    while (true)
    {
        if (packetFile.eof())
        {
            packetFile.clear(); // Reset stream error flags

            // truncate the file every time the thread reaches its end
            if (packetFile.tellg() != std::ios::beg)
                truncatePacketFile();

            packetFile.seekg(0, std::ios::beg);
            // locking the queue until new packets arrive
            if (!pending)
            {
                this->m_queueMutex.lock();
                pending = true;
            }
            continue;
        }

        // reading packet size and data
        while (!this->areBytesAvailable(packetFile, sizeof(packetSize))); { (void)0; }
        packetFile.read(reinterpret_cast<char*>(&packetSize), sizeof(packetSize));
        rawPacket.resize(packetSize);
        while (!this->areBytesAvailable(packetFile, packetSize)); { (void)0; }
        packetFile.read(rawPacket.data(), packetSize);

        if (pending)
            pending = false;
        else
            this->m_queueMutex.lock();

        this->m_packetQueue.push(rawPacket);
        this->m_queueMutex.unlock();
    }

    packetFile.close();
}


void PacketExtractor::truncatePacketFile() const
{
    if (!DeviceIoControl(m_deviceHandle, IOCTL_TRUNCATE_FILE, NULL, 0, NULL, 0, NULL, NULL)) [[unlikely]]
        throw std::runtime_error("Please run the driver prior to running the IDPS.");
}


std::vector<char> PacketExtractor::getPacket() noexcept
{
    // loading new packet
    this->m_queueMutex.lock();
    const std::vector<char> toReturn = std::move(this->m_packetQueue.front()); // Move a reference instead of copying
    this->m_packetQueue.pop();
    this->m_queueMutex.unlock();

    return toReturn;
}


// HELPER FUNCTIONS


bool PacketExtractor::areBytesAvailable(std::ifstream& file, const uint16_t numBytes) noexcept
{
    const std::streampos currentPos = file.tellg();
    file.seekg(0, std::ios::end);
    const std::streampos endPos = file.tellg();
    file.seekg(currentPos, std::ios::beg);
    return (endPos - currentPos) >= numBytes;
}


// SINGLETON METHODS


PacketExtractor::~PacketExtractor() noexcept
{
    CloseHandle(m_deviceHandle); // No need to validate before or after closing
}

PacketExtractor& PacketExtractor::getInstance() noexcept
{
    static PacketExtractor instance;
    return instance;
}

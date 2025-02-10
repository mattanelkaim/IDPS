#include "PacketExtractor.h"
#include <fstream>

PacketExtractor::PacketExtractor() : m_extractorThread(&PacketExtractor::threadRoutine, this)
{
    this->m_extractorThread.detach(); // letting packet extractor thread work in the background
}

void PacketExtractor::threadRoutine()
{
    std::ifstream packetFile("C:\\Users\\nick_\\Desktop\\VMShared\\packetFlow.bin", std::ios::binary);
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
                //DeviceCommunicator::getInstance().truncateFile();

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
}

std::vector<char> PacketExtractor::getPacket() noexcept
{
    // loading new packet
	while (this->m_packetQueue.empty()); { (void)0; }
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

PacketExtractor& PacketExtractor::getInstance() noexcept
{
    static PacketExtractor instance;
    return instance;
}

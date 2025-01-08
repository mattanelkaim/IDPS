#include "PacketExtractor.h"

PacketExtractor::PacketExtractor() noexcept : packetQueue(), queueMutex()
{
	this->ExtractorThread = std::thread(&PacketExtractor::threadRoutine, this);
	this->ExtractorThread.detach(); // thread works in the background
}

void PacketExtractor::threadRoutine() noexcept
{
}

PacketExtractor& PacketExtractor::getInstance() noexcept
{
	static PacketExtractor instance;
	return instance;
}

std::vector<const uint8_t> PacketExtractor::getPacket()
{
    std::vector<const uint8_t> toReturn;

    if (this->packetQueue.empty())
    {
        
    }

    this->queueMutex.lock();
    toReturn = this->packetQueue.front();
    this->packetQueue.pop();
    this->queueMutex.unlock();
    return toReturn;
}

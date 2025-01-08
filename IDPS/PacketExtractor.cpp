#include "PacketExtractor.h"

RawPacket PacketExtractor::getPacket()
{
    RawPacket toReturn;

    if (this->packetQueue.empty())
    {
        
    }

    this->queueMutex.lock();
    toReturn = this->packetQueue.front();
    this->packetQueue.pop();
    this->queueMutex.unlock();
    return toReturn;
}

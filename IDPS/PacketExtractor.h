#pragma once

#include "Helper.h"
#include <thread>
#include <queue>
#include <mutex>

typedef struct RawPacket
{
	byte data[65536];
	uint16_t size;
} RawPacket;

class PacketExtractor
{
private:
	std::mutex queueMutex;
	std::queue<RawPacket> packetQueue;
	std::thread packetExtractorThread;

public:
	RawPacket getPacket() noexcept;
};


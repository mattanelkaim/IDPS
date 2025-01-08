#pragma once

#include "Helper.h"
#include <thread>
#include <queue>
#include <mutex>

using byte = unsigned char;

struct RawPacket
{
	uint16_t size;
	byte data[65536];
};

class PacketExtractor
{
private:
	std::mutex queueMutex;
	std::queue<RawPacket> packetQueue;
	std::thread packetExtractorThread;

public:
	RawPacket getPacket() noexcept;
};


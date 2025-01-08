#pragma once

#include "Helper.h"
#include <thread>
#include <queue>
#include <vector>
#include <mutex>

class PacketExtractor final
{
private:
	std::mutex queueMutex;
	std::queue<std::vector<const uint8_t>> packetQueue;
	std::thread ExtractorThread;

	PacketExtractor() noexcept = default;

public:
	// singelton functions
	PacketExtractor(const PacketExtractor& other) = delete;
	void operator=(const PacketExtractor& other) = delete;
	~PacketExtractor() noexcept = default;

	// methods
	static PacketExtractor& getInstance() noexcept;
	std::vector<const uint8_t> getPacket() noexcept;
};


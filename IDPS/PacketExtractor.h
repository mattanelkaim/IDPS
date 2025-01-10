#pragma once

#include "../Driver/LayerHandles.h"
#include <thread>
#include <queue>
#include <vector>
#include <mutex>
#include <atomic>

class PacketExtractor final
{
private:
	std::queue<std::vector<char>> packetQueue;
	std::thread extractorThread;
	std::mutex queueMutex;
	HANDLE deviceHandle;

	// private methods
	PacketExtractor() noexcept;
	void threadRoutine();
	void truncatePacketFile() const noexcept;
	static bool bytesAvailable(std::ifstream& file, uint16_t numBytes) noexcept;

public:

	// singelton methods
	PacketExtractor(const PacketExtractor& other) = delete;
	void operator=(const PacketExtractor& other) = delete;
	~PacketExtractor() noexcept;

	// methods
	static PacketExtractor& getInstance() noexcept;
	std::vector<char> getPacket() noexcept;
};


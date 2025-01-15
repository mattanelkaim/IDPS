#pragma once

#include "../Driver/LayerHandles.h"
#include <cstdint>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class PacketExtractor final
{
private:
	std::mutex m_queueMutex;
	std::queue<std::vector<char>> m_packetQueue;
	std::thread m_extractorThread;
	HANDLE m_deviceHandle;

	// private methods
	PacketExtractor();
	void threadRoutine();
	void truncatePacketFile() const;
	static bool areBytesAvailable(std::ifstream& file, uint16_t numBytes) noexcept;

public:
	// singelton methods
	~PacketExtractor() noexcept;
	static PacketExtractor& getInstance() noexcept;
	PacketExtractor(const PacketExtractor& other) = delete;
	void operator=(const PacketExtractor& other) = delete;

	// methods
	std::vector<char> getPacket() noexcept;
};


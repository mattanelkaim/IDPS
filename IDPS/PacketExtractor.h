#pragma once

#include <cstdint>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class PacketExtractor final
{
private:
	std::mutex m_queueMutex;
	std::queue<std::vector<uint8_t>> m_packetQueue;
	std::thread m_extractorThread;

	// private methods
	PacketExtractor();
	void threadRoutine();
	static bool areBytesAvailable(std::ifstream& file, uint16_t numBytes) noexcept;

public:
	// singleton methods
	~PacketExtractor() noexcept = default;
	static PacketExtractor& getInstance() noexcept;
	PacketExtractor(const PacketExtractor& other) = delete;
	void operator=(const PacketExtractor& other) = delete;

	// methods
	std::vector<uint8_t> getPacket() noexcept;
};


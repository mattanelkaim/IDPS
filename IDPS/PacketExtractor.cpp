#include "PacketExtractor.h"
#include <fstream>

PacketExtractor::PacketExtractor() noexcept : packetQueue(), queueMutex(), extractorThread(&PacketExtractor::threadRoutine, this)
{
	this->extractorThread.detach(); // letting packet extractor thread work in the background

	// obtaining a device handle to the driver
	this->deviceHandle = CreateFileW(L"\\\\.\\SnifferDeviceLink", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
	if (this->deviceHandle == INVALID_HANDLE_VALUE)
		throw std::runtime_error("Please run the driver prior to running the IDPS.");
}

void PacketExtractor::threadRoutine()
{
	uint16_t packetSize = 0;
	std::vector<char> rawPacket;
	bool pending = false;
	std::ifstream packetFile(PACKET_FILE_PATH, std::ios::binary);

	if (!packetFile.is_open())
		throw std::runtime_error("Error opening packet file.");

    while (true)
    {
		if (packetFile.eof())
		{
			packetFile.clear();

			// truncate the file every time the thread reaches its end
			if (packetFile.tellg() != std::ios::beg)
				truncatePacketFile();

			packetFile.seekg(0, std::ios::beg);
			// locking the queue until new packets arrive
			if (!pending)
			{
				this->queueMutex.lock();
				pending = true;
			}
			continue;
		}

		// reading packet size and data
		while (!this->bytesAvailable(packetFile, sizeof(packetSize))); { (void)0; }
		packetFile.read(reinterpret_cast<char*>(&packetSize), sizeof(packetSize));
		rawPacket.resize(packetSize);
		while (!this->bytesAvailable(packetFile, packetSize)); { (void)0; }
		packetFile.read(rawPacket.data(), packetSize);

		if (pending)
			pending = false;
		else
			this->queueMutex.lock();

		this->packetQueue.push(rawPacket);
		this->queueMutex.unlock();
	}

	packetFile.close();
}

void PacketExtractor::truncatePacketFile() const noexcept
{
	if (!DeviceIoControl(deviceHandle, IOCTL_TRUNCATE_FILE, NULL, 0, NULL, 0, NULL, NULL));
		throw std::runtime_error("Please run the driver prior to running the IDPS.");
}

bool PacketExtractor::bytesAvailable(std::ifstream& file, const uint16_t numBytes) noexcept
{
    const std::streampos currentPos = file.tellg();
    file.seekg(0, std::ios::end);
	const std::streampos endPos = file.tellg();
    file.seekg(currentPos, std::ios::beg);
    return (endPos - currentPos) >= numBytes;
}

PacketExtractor::~PacketExtractor() noexcept
{
	CloseHandle(deviceHandle); // No need to validate before or after closing
}

PacketExtractor& PacketExtractor::getInstance() noexcept
{
	static PacketExtractor instance;
	return instance;
}

std::vector<char> PacketExtractor::getPacket() noexcept
{
    std::vector<char> toReturn;

	// loading new packet
    this->queueMutex.lock();
    toReturn = this->packetQueue.front();
    this->packetQueue.pop();
    this->queueMutex.unlock();

    return toReturn;
}

#pragma once

#include "Packets/Packet.h"

class Distributer
{
private:
	Distributer() noexcept = default;

public:
	// singleton methods
	~Distributer() noexcept = default;
	inline static Distributer& getInstance() noexcept;
	Distributer(const Distributer& other) = delete;
	void operator=(const Distributer& other) = delete;

    // methods
    void run() const;
    static bool isArpPacket(const Packet& packet) noexcept;
	static bool isTcpPacket(const Packet& packet) noexcept;
	static bool isDnsPacket(const Packet& packet) noexcept;
};


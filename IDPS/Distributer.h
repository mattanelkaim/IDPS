#pragma once

#include "Packets/Packet.h"

class Distributer final
{
private:
	Distributer() noexcept = default;

public:
	// singleton methods
	~Distributer() noexcept = default;
	static Distributer& getInstance() noexcept;
	Distributer(const Distributer& other) = delete;
	void operator=(const Distributer& other) = delete;

    // methods
    void run() const;
};


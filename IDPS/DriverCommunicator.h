#pragma once

#include "../Driver/LayerHandles.h"
#include "Helper.h"

class DriverCommunicator final
{
private:
    HANDLE m_deviceHandle;

	DriverCommunicator();

public:
	// singelton methods
	~DriverCommunicator() noexcept;
	static DriverCommunicator& getInstance() noexcept;
	DriverCommunicator(const DriverCommunicator& other) = delete;
	void operator=(const DriverCommunicator& other) = delete;

    // methods
    void addIpToFirewall(uint32_t ip) const;
	void addMacToFirewall(mac macAddr) const;
    void truncateFile() const;
};
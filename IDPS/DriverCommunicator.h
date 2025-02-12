#pragma once

// do NOT sort these includes
#include "Helper.h"
#include "../Driver/LayerHandles.h"

class DriverCommunicator final
{
private:
    HANDLE m_deviceHandle;

	DriverCommunicator();

public:
	// singelton methods
	~DriverCommunicator() noexcept;
	inline static DriverCommunicator& getInstance() noexcept;
	DriverCommunicator(const DriverCommunicator& other) = delete;
	void operator=(const DriverCommunicator& other) = delete;

    // methods
    void addIpToFirewall(uint32_t ip) const;
	void addMacToFirewall(mac macAddr) const;
    void truncateFile() const;
};
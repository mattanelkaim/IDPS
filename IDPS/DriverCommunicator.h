#pragma once

// Do NOT sort these includes
#include "Helper.h"
#include "../Driver/LayerHandles.h"

class DriverCommunicator final
{
private:
    HANDLE m_deviceHandle;

    DriverCommunicator();

public:
    // Singleton methods
    ~DriverCommunicator() noexcept;
    static DriverCommunicator& getInstance();
    DriverCommunicator(const DriverCommunicator& other) = delete;
    void operator=(const DriverCommunicator& other) = delete;
    DriverCommunicator(DriverCommunicator&& other) = delete;
    void operator=(DriverCommunicator&& other) = delete;

    // methods
    void addIpToFirewall(uint32_t ip) const;
    void addMacToFirewall(mac macAddr) const;
    void truncateFile() const;
};
#include "DriverCommunicator.h"
#include <stdexcept>

DriverCommunicator::DriverCommunicator() :
    m_deviceHandle(CreateFileW(L"\\\\.\\SnifferDeviceLink", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL))
{
    if (m_deviceHandle == INVALID_HANDLE_VALUE)
        throw std::runtime_error("Please run the driver prior to running the IDPS.");
}

DriverCommunicator::~DriverCommunicator() noexcept
{
    CloseHandle(m_deviceHandle);
}

DriverCommunicator& DriverCommunicator::getInstance() noexcept
{
    static DriverCommunicator instance;
    return instance;
}

void DriverCommunicator::addIpToFirewall(uint32_t ip) const
{
    if (!DeviceIoControl(m_deviceHandle, IOCTL_SEND_IP_RULE, &ip, sizeof(ip), NULL, 0, NULL, NULL))
        throw std::runtime_error("Failed to add IP to firewall.");
}

void DriverCommunicator::addMacToFirewall(mac macAddr) const 
{
    if (!DeviceIoControl(m_deviceHandle, IOCTL_SEND_MAC_RULE, &macAddr, sizeof(macAddr), NULL, 0, NULL, NULL))
        throw std::runtime_error("Failed to add MAC to firewall.");
}

void DriverCommunicator::truncateFile() const
{
    if (!DeviceIoControl(m_deviceHandle, IOCTL_TRUNCATE_FILE, NULL, 0, NULL, 0, NULL, NULL))
        throw std::runtime_error("Failed to truncate file.");
}

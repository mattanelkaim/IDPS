#pragma once

class Distributer final
{
private:
    Distributer() noexcept = default;

public:
    // Singleton methods
    ~Distributer() noexcept = default;
    static Distributer& getInstance() noexcept;
    Distributer(const Distributer& other) = delete;
    void operator=(const Distributer& other) = delete;

    // methods
    void run() const;
};

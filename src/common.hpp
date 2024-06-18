#pragma once

class non_copyable {
   public:
    non_copyable(non_copyable&) = delete;
    non_copyable& operator=(non_copyable&) = delete;

   protected:
    non_copyable() = default;
    ~non_copyable() = default;
};

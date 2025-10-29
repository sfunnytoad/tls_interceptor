#pragma once

#include <mutex>
#include <unordered_map>

template<typename K, typename V> class ConcurrentMap
{
public:
    void add(K key, const V& value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.insert(std::make_pair(key, value));
    }

    void remove(K key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        map_.erase(key);
    }

    bool lookup(K key, V& value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = map_.find(key);
        if (iter == map_.end())
            return false;

        value = iter->second;
        return true;
    }

private:
    std::mutex mutex_;
    std::unordered_map<K, V> map_;
};

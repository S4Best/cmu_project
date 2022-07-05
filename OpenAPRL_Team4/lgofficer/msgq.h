#pragma once

#include <iostream>
#include <deque>
#include <memory>
#include <mutex>
#include <condition_variable>

template<typename T>
class Msgq {
public:
    Msgq() :wakeup_(false) {}
    ~Msgq() {}

    void enqueue(std::shared_ptr<T> ptrMsg) {
        qmtx_.lock();
        try {
            std::cout << " msgq before enq size : " << msgq_.size() << std::endl;
            msgq_.push_back(ptrMsg);
            wakeup_ = true;
            std::cout << " msgq after enq size : " << msgq_.size() << std::endl;
        }
        catch (std::exception& e) {
            std::cout << "enqueue exception is occurred:" << e.what() << std::endl;
        }
        qmtx_.unlock();
        qcv_.notify_one();
    }

    void wait() {
        std::unique_lock<std::mutex> lk(qmtx_);
        std::cout << " waiting..." << std::endl;
        qcv_.wait(lk, [&] { return wakeup_ == true; });
        std::cout << " waiting end, wakeup" << std::endl;
        wakeup_ = false;
        lk.unlock();
    }

    bool isEmpty() {
        bool isEmptyFlag = false;
        qmtx_.lock();
        isEmptyFlag = msgq_.empty();
        qmtx_.unlock();
        return isEmptyFlag;
    }

    std::shared_ptr<T> dequeue() {
        std::shared_ptr<T> ptrMsg = nullptr;
        qmtx_.lock();
        try {
            if (!msgq_.empty()) {
                ptrMsg = msgq_.front();
                msgq_.pop_front();
            }
        }
        catch (std::exception& e) {
            std::cout << "dequeue exception is occurred:" << e.what() << std::endl;
        }
        qmtx_.unlock();
        return ptrMsg;
    }

    void clearQueue()
    {
        qmtx_.lock();
        msgq_.clear();
        wakeup_ = false;
        qmtx_.unlock();
    }

protected:
    bool wakeup_;
    std::mutex qmtx_;
    std::deque<std::shared_ptr<T>> msgq_;
    std::condition_variable qcv_;
};
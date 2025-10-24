//
// Created by Вероника on 03.09.2025.
//

#ifndef FILE_SCANNER_SCANNER_H
#define FILE_SCANNER_SCANNER_H

#pragma once

#include <string>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>


#ifdef SCANNER_LIB_EXPORTS
#define SCANNER_API __declspec(dllexport)
#else
#define SCANNER_API __declspec(dllimport)
#endif

struct SCANNER_API ScanResult {
    size_t processed_files = 0;
    size_t malicious_files = 0;
    size_t errors = 0;
    double scan_time_sec = 0.0;
};

class SCANNER_API Scanner {
public:
    ScanResult& get_results_for_update() { return results_; }
    Scanner(const std::string& scan_path, const std::string& db_path, const std::string& log_path);

    void scan();

    ScanResult get_results() const;
    std::string check_hash(const std::string& hash) const;
    void load_database();

private:
    void process_file(const std::string& file_path);
    void recursive_scan(const std::string& path);
    void worker_thread();
    std::string scan_path_;
    std::string db_path_;
    std::string log_path_;
    ScanResult results_;
    std::unordered_map<std::string, std::string> malicious_hashes_;
    std::ofstream log_file_;
    std::queue<std::string> file_queue_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    bool done_adding_files_ = false;
    std::vector<std::thread> worker_threads_;
};

#endif

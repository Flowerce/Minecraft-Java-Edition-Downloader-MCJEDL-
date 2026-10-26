#include "sha1.h"

#include <cstddef>
#include <cstdlib>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <typeinfo>
#include <unordered_map>
#include <vector>

#if defined(__GNUG__)
#  include <cxxabi.h>
#endif

#include <curl/curl.h>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

std::string demangle(const char* name) {
#if defined(__GNUG__)
    int status = 0;
    std::unique_ptr<char, void(*)(void*)> res{
        abi::__cxa_demangle(name, nullptr, nullptr, &status),
        std::free
    };
    return (status == 0 && res) ? res.get() : name;
#else
    return name;   // MSVC 已经是可读的
#endif
}

void print_exception(const std::exception& e, int level = 0) {
    std::cerr << std::string(level * 2, ' ')
              << "-> [" << demangle(typeid(e).name()) << "] "
              << e.what() << '\n';

    try { std::rethrow_if_nested(e); }
    catch (const std::exception& n) { print_exception(n, level + 1); }
    catch (...) {
        std::cerr << std::string((level + 1) * 2, ' ') << "-> (non-std exception)\n";
    }
}

std::string file_sha1(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";

    SHA1 sha;
    std::vector<unsigned char> buffer(64 * 1024); // 64 KB 缓冲区

    // 1. 分块读取文件，送入 SHA1 对象
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount() > 0) {
        sha.Input(buffer.data(), static_cast<unsigned>(file.gcount()));
    }

    // 2. 获取 160-bit (20 字节) 的摘要结果
    unsigned int digest[5];
    if (!sha.Result(digest)) {
        return ""; // 计算失败
    }

    // 3. 将 5 个 32-bit 整数转换为 40 位十六进制字符串
    std::ostringstream oss;
    for (int i = 0; i < 5; ++i) {
        oss << std::hex << std::setw(8) << std::setfill('0') << digest[i];
    }
    return oss.str();
}

class CurlGlobal {
private:
    static int count;

public:
    CurlGlobal() { 
        try {
            if (!count++ && curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
                throw std::runtime_error("Can't initialize curl_global!");
            }
        } catch (...) {
            --count;
            throw;
        }
    }

    ~CurlGlobal() {
        if (!--count) {
            curl_global_cleanup();
        }
    }
};

class CurlMulti;

class CurlEasy {

    friend CurlMulti;
    
private:

    CURL* curl;
    std::unique_ptr<std::ostream> f;
    std::string url;
    SHA1 sha;
    std::size_t transmitted_size;
    std::string raw_url;
    
    static std::size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
        auto& self = *static_cast<CurlEasy*>(userdata);
        const size_t total = size * nmemb;
        if (self.f == nullptr) {
            try {
                auto ofs = std::make_unique<std::ofstream>(last_segment(self.url), std::ios::binary);
                if (!ofs->is_open()) {
                    throw std::runtime_error("Can't open local file for writing: " + last_segment(self.url));
                }
                self.f = std::move(ofs);
            } catch (const std::exception& e) {
                print_exception(e);
                return 0;
            }
        }
        self.f->write(reinterpret_cast<char*>(ptr), total);
        if (!*(self.f)) {
            return 0;  // 让 libcurl 判定为 CURLE_WRITE_ERROR 并中止传输
        }
        self.sha.Input(reinterpret_cast<unsigned char*>(ptr), static_cast<unsigned>(total));
        self.transmitted_size += total;
        return total;  // 成功时返回值必须严格等于 size * nmemb
    }

    static std::string last_segment(std::string_view url) {
        auto p = url.find_last_of('/');
        if (p == std::string_view::npos) return std::string(url);
        return std::string(url.substr(p + 1));
    }

public:

    typedef std::string& (*URL_Replacer)(std::string&);

    CurlEasy(const std::string& s = "", 
            std::unique_ptr<std::ostream> stream = nullptr) 
            : curl(nullptr), transmitted_size(0) {
        curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Can't initialize curl_easy!");
        }
        SetURL(s);
        f = std::move(stream);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
        curl_easy_setopt(curl, CURLOPT_PRIVATE, this);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    }

    virtual ~CurlEasy() { curl_easy_cleanup(curl); }

    CurlEasy& SetURL(const std::string& s) {
        url = raw_url = s;
        if (url_replacer) {
            url_replacer(url);
        }
        curl_easy_setopt(curl, CURLOPT_URL, url.empty() ? nullptr : url.c_str());
        return *this;
    }

    std::string Perform() {
        sha.Reset();
        transmitted_size = 0;
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            throw std::runtime_error(
            std::string("Can't download file: ") + url +
            " (" + curl_easy_strerror(res) + ", code " +
            std::to_string(static_cast<int>(res)) + ")");
        }

        // 2. 获取 160-bit (20 字节) 的摘要结果
        unsigned int digest[5];
        if (!sha.Result(digest)) {
            return ""; // 计算失败
        }

        // 3. 将 5 个 32-bit 整数转换为 40 位十六进制字符串
        std::ostringstream oss;
        for (int i = 0; i < 5; ++i) {
            oss << std::hex << std::setw(8) << std::setfill('0') << digest[i];
        }
        return oss.str();
    }

    std::unique_ptr<std::ostream> ExchangeStream(
            std::unique_ptr<std::ostream> incoming) noexcept {
        auto outgoing = std::move(f);
        f = std::move(incoming);
        return outgoing;
    }

    static URL_Replacer SetURL_Replacer(URL_Replacer fn) {
        URL_Replacer temp = url_replacer;
        url_replacer = fn;
        return temp;
    }

    private:
        static URL_Replacer url_replacer;
};

CurlEasy::URL_Replacer CurlEasy::url_replacer = nullptr;

class CurlMulti {
private:

    CURLM *multi;
    
    struct TaskInfo {
        std::string url;
        std::size_t size;
        std::string sha1;
    };
    std::unordered_map<fs::path, TaskInfo> tasks;
    struct TaskHandle {
        TaskInfo* p;
    };
    
    struct EasyTaskWrapper : public CurlEasy, public TaskHandle {
    public:
        EasyTaskWrapper(const std::string& s = "", 
            std::unique_ptr<std::ostream> stream = nullptr, 
                TaskHandle t = {nullptr}) : CurlEasy(s, std::move(stream)), TaskHandle{t.p}, retry_count(0) {}
        int retry_count;
        std::unordered_map<fs::path, TaskInfo>::iterator it_;
    };
    std::vector<std::unique_ptr<EasyTaskWrapper>> easy;
    int transmitted_fileCount;
    std::size_t transmitted_size;
    std::size_t* extra_data;
    std::unordered_map<fs::path, TaskInfo>::iterator it_;
    
    void Prepare(EasyTaskWrapper* e, bool is_retrying = false) {
        e->sha.Reset();
        e->transmitted_size = 0;
        if (!is_retrying) {
            e->it_ = it_;
        }
        e->p = &e->it_->second;
        e->SetURL(e->it_->second.url);
        if (e->f == nullptr) {
            e->f = std::make_unique<std::ofstream>();
        }
        auto& ofs = dynamic_cast<std::ofstream&>(*e->f.get());
        auto parent = e->it_->first.parent_path();
        if (!parent.empty()) {
            std::error_code ec;
            fs::create_directories(parent, ec);
            if (ec) {
                throw fs::filesystem_error("fs::create_directories", parent, ec);
            }
        }
        ofs.clear();
        ofs.open(e->it_->first, std::ios::binary);
        if (!ofs.is_open()) {
            throw std::runtime_error("Can't open local file for writing: " + e->it_->first.string());
        } 
        CURLMcode mc = curl_multi_add_handle(multi, e->curl);
        if (mc != CURLM_OK) {
            throw std::runtime_error(std::string("curl_multi_add_handle: ") + curl_multi_strerror(mc));
        }
    }

    static bool Check(EasyTaskWrapper* e) {
        if (e->p == nullptr) return true;
        if (e->p->size != 0 && e->p->size != e->transmitted_size) {
            return false;
        }

        if (e->p->sha1.empty()) return true;

        unsigned int digest[5];
        if (!e->sha.Result(digest)) {
            return false;
        }

        std::ostringstream oss;
        for (int i = 0; i < 5; ++i) {
            oss << std::hex << std::setw(8) << std::setfill('0') << digest[i];
        }

        if (e->p->sha1 != oss.str()) {
            return false;
        }
        return true;
    }

public:

    CurlMulti() : multi(nullptr), callback_(nullptr), 
            transmitted_fileCount(0), transmitted_size(0), extra_data(nullptr) {
        multi = curl_multi_init();
        if (!multi) {
            throw std::runtime_error("Can't initialize curl_multi!");
        }
    }

    virtual ~CurlMulti() {
        for (auto& e : easy) {
            curl_multi_remove_handle(multi, e->curl);
        }
        curl_multi_cleanup(multi);
    }
    
    CurlMulti& AddTask(const std::string& url, fs::path filename = "", 
            std::size_t size = 0, const std::string& sha1 = "") {
        if (filename.empty()) {
            filename = CurlEasy::last_segment(url);
        }
        tasks[filename] = {url, size, sha1};
        return *this;
    }

    CurlMulti& AddStream(std::unique_ptr<std::ofstream> stream = nullptr) {
        if (stream && stream->is_open())
            throw std::invalid_argument("AddStream: stream must not be opened; "
                                    "output path is decided by AddURL");
                                    
        auto e = std::make_unique<EasyTaskWrapper>("", std::move(stream));
        //curl_multi_add_handle(multi, e->curl);
        easy.push_back(std::move(e));
        return *this;
    }

    void Perform() {
        if (tasks.empty()) {
            return;
        }
        it_ = tasks.begin();

        if (easy.empty())
            throw std::runtime_error("CurlMulti::Perform: Tasks queued but no worker (AddStream)");
            
        for (auto& e : easy) {
            if (it_ != tasks.end()) {
                Prepare(e.get());
                ++it_;
            } else {
                break;
            }
        }
    
        int still_running;
        do {
            CURLMcode mresult = curl_multi_perform(multi, &still_running);
            if (mresult != CURLM_OK) {
                throw std::runtime_error("Failed when calling curl_multi_perform()!");
            }

            bool more_work = false;
            CURLMsg *msg;
            int msgs_left;
            while ((msg = curl_multi_info_read(multi, &msgs_left)) != NULL) {
                if (msg->msg == CURLMSG_DONE) {               // 5. 收割                    
                    CurlEasy* e;
                    curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &e);
                    EasyTaskWrapper* const etw = dynamic_cast<EasyTaskWrapper*>(e);
                    std::ofstream& ofs = dynamic_cast<std::ofstream&>(*e->f.get());
                    ofs.close();
                    
                    CURLcode result = msg->data.result;
                    curl_multi_remove_handle(multi, msg->easy_handle);                    
                    if (result != CURLE_OK || ofs.fail() || !Check(etw)) {
                        if (++etw->retry_count < 3) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            Prepare(etw, true);
                            continue;
                        }
                        throw std::runtime_error(
                            "Download failed: " + e->url +
                            " (" + curl_easy_strerror(msg->data.result) + ", code " +
                            std::to_string(static_cast<int>(msg->data.result)) + ")");
                    }
                    ++transmitted_fileCount;
                    transmitted_size += e->transmitted_size;
                    if (callback_) {
                        callback_(transmitted_fileCount, transmitted_size, extra_data);
                    }
                    if (it_ != tasks.end()) {
                        Prepare(dynamic_cast<EasyTaskWrapper*>(e));
                        ++it_;
                        more_work = true;
                    } else {
                        /*auto it = std::find_if(easy.begin(), easy.end(), 
                        [e](const std::unique_ptr<CurlEasy>& p) { return p.get() == e; });
                        if (it != easy.end()) {
                            easy.erase(it);
                        }*/
                    }
                    // 处理 msg->data.result，然后清理或复用 easy
                }
            }
            
            if (still_running) {
                mresult = curl_multi_poll(multi, nullptr, 0, 1000, nullptr);
                if (mresult != CURLM_OK) {
                    throw std::runtime_error("Failed when calling curl_multi_pool()!");
                }
            } else if (!more_work) {
                break;
            }
        } while (true);
    }

    typedef void (*Callback)(int fileCount, std::size_t size, std::size_t*);
    Callback SetCallback(Callback callback, std::size_t* arg) {
        Callback temp = callback_;
        callback_ = callback;
        extra_data = arg;
        return temp; 
    }

private:
    Callback callback_;
};

int CurlGlobal::count = 0;
CurlGlobal curl_global_instance;

std::string extract_host(const std::string& url, std::string::size_type& pos, std::string::size_type& len) {
    auto p1 = url.find("//");
    if (p1 != std::string::npos) {
        pos = p1 + 2;
    } else {
        pos = 0;
    }
    auto p2 = url.find('/', pos);
    if (p2 != std::string::npos) {
        len = p2 - pos;
    } else {
        len = url.length() - pos;
    }
    return url.substr(pos, len);
}

std::string& to_bmclapi(std::string& url) {
    static const std::unordered_map<std::string, std::string> host_map = {
        {"piston-data.mojang.com", "bmclapi2.bangbang93.com"},
        {"launchermeta.mojang.com", "bmclapi2.bangbang93.com"},
        {"launcher.mojang.com",      "bmclapi2.bangbang93.com"},
        {"resources.download.minecraft.net", "bmclapi2.bangbang93.com/assets"},
        {"libraries.minecraft.net", "bmclapi2.bangbang93.com/maven"}
    };
    
    std::string::size_type pos, len;
    std::string host = extract_host(url, pos, len);
    if (host_map.contains(host)) {
        url.replace(pos, len, host_map.at(host));
    }
    
    return url;
}

struct VersionManifest_v2 {
    struct Latest {
        std::string release;
        std::string snapshot;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(Latest, release, snapshot)
    };
    
    struct Version {
        std::string id;
        std::string type;
        std::string url;
        std::string time;
        std::string releaseTime;
        std::string sha1;
        json::number_integer_t complianceLevel;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(Version, id, type, url, time, releaseTime, sha1, complianceLevel)    
    };

    Latest latest;
    std::vector<Version> versions;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(VersionManifest_v2, latest, versions)
};

struct VersionDefinition {
    struct Arguments {
        struct JVM {
            struct Rule {
                struct OS {
                    struct VersionRange {
                        std::string min;
                        std::string max;
                        NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(VersionRange, min, max)
                    };
                    std::string name;
                    std::string version;
                    VersionRange versionRange;
                    std::string arch;
                    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(OS, name, version, versionRange, arch)
                };
                std::string action;
                OS os;
                NLOHMANN_DEFINE_TYPE_INTRUSIVE(Rule, action, os)
            };
            std::vector<Rule> rules;
            std::vector<std::string> value;
            
            friend void from_json(const json& j, JVM& m) {
                if (j.is_string()) {
                    m.value.push_back(j.get<std::string>());
                    return;
                } else if (j.is_object()) {
                    if (j.contains("rules")) {
                        j.at("rules").get_to(m.rules);
                    }
                } else {
                    throw json::type_error::create(
                        302, std::string("type must be string or object, but is ") + j.type_name(), &j);
                }

                const auto& v = j.at("value");
                if (v.is_string()) {
                    m.value.push_back(v.get<std::string>());
                } else if (v.is_array()) {
                    m.value = v.get<std::vector<std::string>>();
                } else {
                    throw json::type_error::create(
                        302, std::string("type must be string or array, but is ") + v.type_name(), &v);
                }
            }
        };
        struct Game {
            struct Rule {
                std::string action;
                std::map<std::string, bool> features;
                NLOHMANN_DEFINE_TYPE_INTRUSIVE(Rule, action, features)
            };
            std::vector<Rule> rules;
            std::vector<std::string> value;

            friend void from_json(const json& j, Game& g) {
                if (j.is_string()) {
                    g.value.push_back(j.get<std::string>());
                    return;
                } else if (j.is_object()) {
                    j.at("rules").get_to(g.rules);
                } else {
                    throw json::type_error::create(
                        302, std::string("type must be string or object, but is ") + j.type_name(), &j);
                }

                const auto& v = j.at("value");
                if (v.is_string()) {
                    g.value.push_back(v.get<std::string>());
                } else if (v.is_array()) {
                    g.value = v.get<std::vector<std::string>>();
                } else {
                    throw json::type_error::create(
                        302, std::string("type must be string or array, but is ") + v.type_name(), &v);
                }
            }
        };
        
        std::vector<JVM> default_user_jvm;
        std::vector<Game> game;
        std::vector<JVM> jvm;
        
        friend void from_json(const json& j, Arguments& arg) {
            if (j.contains("default-user-jvm")) {
                j.at("default-user-jvm").get_to(arg.default_user_jvm);
            }
            j.at("game").get_to(arg.game);
            j.at("jvm").get_to(arg.jvm);
        }
    } arguments;
    struct AssetIndex {
        std::string id;
        std::string sha1;
        json::number_integer_t size;
        json::number_integer_t totalSize;
        std::string url;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(AssetIndex, id, sha1, size, totalSize, url)
    } assetIndex;
    std::string assets;
    json::number_integer_t complianceLevel;
    struct Downloads {
        struct Download {
            std::string sha1;
            json::number_integer_t size;
            std::string url;
            NLOHMANN_DEFINE_TYPE_INTRUSIVE(Download, sha1, size, url)
        };
        Download client;
        Download client_mappings;
        Download server;
        Download server_mappings;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Downloads, client, client_mappings, server, server_mappings)
    } downloads;
    std::string id;
    struct JavaVersion {
        std::string component;
        json::number_integer_t majorVersion;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(JavaVersion, component, majorVersion)
    } javaVersion;
    struct Library {
        struct Downloads {
            struct Artifact {
                std::string path;
                std::string sha1;
                json::number_integer_t size;
                std::string url;
                NLOHMANN_DEFINE_TYPE_INTRUSIVE(Artifact, path, sha1, size, url)
            };
            struct Natives {
                std::string path;
                std::string sha1;
                json::number_integer_t size;
                std::string url;
                NLOHMANN_DEFINE_TYPE_INTRUSIVE(Natives, path, sha1, size, url)
            };
            struct Extract {
                std::vector<std::string> exclude;
                NLOHMANN_DEFINE_TYPE_INTRUSIVE(Extract, exclude)
            };
            Artifact artifact;
            std::map<std::string, Natives> classifiers;
            Extract extract;
            NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Downloads, artifact, classifiers, extract)
        };
        struct Downloads downloads;
        std::string name;
        struct Rule {
            std::string action;
            struct OS {
                std::string name;
                NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(OS, name)
            };
            OS os;
            NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Rule, action, os)
        };
        std::vector<Rule> rules;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Library, downloads, name, rules)
    };
    std::vector<Library> libraries;
    struct Logging {
        struct Client {
            std::string argument;
            struct File {
                std::string id;
                std::string sha1;
                json::number_integer_t size;
                std::string url;
                NLOHMANN_DEFINE_TYPE_INTRUSIVE(File, id, sha1, size, url)
            };
            File file;
            std::string type;
            NLOHMANN_DEFINE_TYPE_INTRUSIVE(Client, argument, file, type)
        };
        Client client;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(Logging, client)
    } logging;
    std::string mainClass;
    std::string minecraftArguments;
    json::number_integer_t minimumLauncherVersion;
    std::string releaseTime;
    std::string time;
    std::string type;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(VersionDefinition,
        arguments, assetIndex, assets, complianceLevel, downloads, id, 
        javaVersion, libraries, logging, mainClass, minecraftArguments,
        minimumLauncherVersion, releaseTime, time, type)
};

struct AssetIndex {
    bool map_to_resources;
    struct ObjectInfo {
        std::string hash;
        json::number_integer_t size;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(ObjectInfo, hash, size)
    };
    std::unordered_map<std::string, ObjectInfo> objects;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(AssetIndex, map_to_resources, objects)
};

std::string current_os_name() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "osx";
#else
    return "linux";
#endif
}

bool library_allowed(const std::vector<VersionDefinition::Library::Rule>& rules) {
    if (rules.empty()) return true;          // 无 rules = 全平台都需要
    const std::string os = current_os_name();
    bool allowed = false;                    // 默认 disallow
    for (const auto& r : rules) {
        // 只按 os.name 匹配；r.os.name 为空表示通配
        if (!r.os.name.empty() && r.os.name != os) continue;
        if (r.action == "allow")         allowed = true;
        else if (r.action == "disallow") allowed = false;
    }
    return allowed;
}

bool check_local_file(fs::path p, std::size_t size, std::string hash) {
    if (fs::exists(p)) {
        if (!size || fs::file_size(p) == size) {
            if (file_sha1(p.string()) == hash) {
                return true;
            }
        }
    }
    return false;
}

std::string formatBytes(std::uint64_t bytes, int precision = 2) {
    static constexpr std::array<const char*, 7> units = {
        "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"
    };
    if (bytes == 0) return "0 B";

    std::size_t idx = 0;
    double value = static_cast<double>(bytes);
    while (value >= 1024.0 && idx + 1 < units.size()) {
        value /= 1024.0;
        ++idx;
    }
    const int prec = (idx == 0) ? 0 : precision;
    return std::format("{:.{}f} {}", value, prec, units[idx]);
}

void report_download_progress(int n, std::size_t size, std::size_t* p_totalSize) {
    std::cout << "\r正在下载……\t已下载 " << n << " 个文件，进度 " 
              << std::fixed << std::setprecision(2) << 100.0 * size / *p_totalSize
              << "%" << std::defaultfloat;
}

void run(int argc, char* argv[]) {
    std::cout << "curl version: " << curl_version() << "\n";

    curl_version_info_data* vi = curl_version_info(CURLVERSION_NOW);

    std::cout << "protocols : ";
    if (vi->protocols) {
        for (const char* const* p = vi->protocols; *p; ++p) {
            std::cout << *p << ' ';
        }
    } else {
        std::cout << "(null)";
    }
    std::cout << "\n";

    std::cout << "ssl backend: " << (vi->ssl_version ? vi->ssl_version : "(none)") << "\n";
    std::cout << "ssl feature: "
              << ((vi->features & CURL_VERSION_SSL) ? "YES" : "NO") << "\n";

    //CurlEasy::SetURL_Replacer(to_bmclapi); // BMCLAPI源几乎总是下载失败，我也不知道为什么

    std::cout << "\n\n==============================================================================\n" << std::endl;
    std::cout << "Minecraft Java 版下载器（MCJEDL）\t版本v1.0\t作者：bilibili@FC_流星" << std::endl;
    std::cout << "\n==============================================================================\n\n" << std::endl;
    std::cout << "正在获取版本信息……" << std::endl;
    auto version_manifest = CurlEasy("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
        std::make_unique<std::ostringstream>());
    version_manifest.Perform();
    std::string vmstring = dynamic_cast<std::ostringstream*>(version_manifest.ExchangeStream(nullptr).get())->str();
    json j = json::parse(vmstring);
    VersionManifest_v2 vm = j.get<VersionManifest_v2>();
    std::cout << "获取版本信息成功！\n\n最新正式版：" << vm.latest.release
              << "\t\t最新测试版：" << vm.latest.snapshot << std::endl;
    
    std::cout << "\n请输入你要下载的版本（留空则默认为最新正式版）：";
    std::string version;
    std::getline(std::cin, version);

    if (version.empty()) {
        version = vm.latest.release;
    }

    auto target = std::find_if(vm.versions.begin(), vm.versions.end(), 
        [&version](const VersionManifest_v2::Version& v) { return v.id == version;});
    if (target == vm.versions.end()) {
        std::cout << "未找到您想要下载的版本！" << std::endl;
        return;
    }

    std::cout << "\n\n" << target->id << " 版本信息\n\n"
              << "类型：\t\t" << target->type << "\n"
              << "发布时间：\t" << target->releaseTime << "\n\n"
              << "确定要下载此版本吗？[y/N] ";

    char ch = '\0';
    std::cin >> ch;
    std::cin.get(); // 丢弃换行符

    if (ch != 'y' && ch != 'Y') {
        return;
    }

    int fileCount = 0; 
    std::size_t totalSize = 0;
    std::cout << "\n正在校验本地文件……" << std::endl;
    fs::path VersionJson = fs::path(".minecraft/versions") / target->id / target->id;
    VersionJson += ".json";
    fs::create_directories(VersionJson.parent_path());
    if (!check_local_file(VersionJson, 0, target->sha1)) {
        std::cout << "正在下载版本 JSON 文件……" << std::endl;
        CurlEasy(target->url, std::make_unique<std::ofstream>(VersionJson, std::ios::binary)).Perform();
    }
    j = json::parse(std::ifstream(VersionJson, std::ios::binary));
    VersionDefinition vd = j.get<VersionDefinition>();

    fs::path Assets = fs::path(".minecraft/assets/indexes") / vd.assetIndex.id;
    Assets += ".json";
    fs::create_directories(Assets.parent_path());
    if (!check_local_file(Assets, vd.assetIndex.size, vd.assetIndex.sha1)) {
        std::cout << "正在下载资源索引文件……" << std::endl;
        CurlEasy(vd.assetIndex.url, std::make_unique<std::ofstream>(Assets, std::ios::binary)).Perform();
    }
    j = json::parse(std::ifstream(Assets, std::ios::binary));
    AssetIndex ai = j.get<AssetIndex>();

    CurlMulti downloader;
    for (int i = 0; i < 64; ++i) {
        downloader.AddStream();
    }

    fs::path Client = fs::path(".minecraft/versions") / target->id / target->id;
    Client += ".jar";
    if (!check_local_file(Client, vd.downloads.client.size, vd.downloads.client.sha1)) {
        ++fileCount;
        totalSize += vd.downloads.client.size;
        downloader.AddTask(vd.downloads.client.url, Client, 
                vd.downloads.client.size, vd.downloads.client.sha1);
    }
    for (const auto& entry : vd.libraries) {
        if (!library_allowed(entry.rules)) continue; 
        if (!entry.downloads.classifiers.empty()) {
            std::string classifiers_key = "natives-" + current_os_name();
            for (const auto& [platform, natives]: entry.downloads.classifiers) {
                if (!platform.starts_with(classifiers_key)) continue;
                fs::path p = fs::path(".minecraft/libraries") / natives.path;
                if (!check_local_file(p, natives.size, natives.sha1)) {
                    ++fileCount;
                    totalSize += natives.size;
                    downloader.AddTask(natives.url, p,
                            natives.size, natives.sha1);                    
                }
            }
        }
        if (entry.downloads.artifact.url.empty()) continue; // 有些条目只有 classifiers
        fs::path p = fs::path(".minecraft/libraries") / entry.downloads.artifact.path;
        if (check_local_file(p, entry.downloads.artifact.size, entry.downloads.artifact.sha1)) continue;
        ++fileCount;
        totalSize += entry.downloads.artifact.size;
        downloader.AddTask(entry.downloads.artifact.url, p,
                entry.downloads.artifact.size, entry.downloads.artifact.sha1);
    }
    for (const auto& [key, value] : ai.objects) {
        fs::path Object = fs::path(".minecraft/assets/objects") / value.hash.substr(0, 2) / value.hash;
        if (vd.assetIndex.id == "pre-1.6" || vd.assetIndex.id == "legacy") {
            Object = fs::path(".minecraft/versions") / vd.id / "resources" / key;
        }
        std::string url = "https://resources.download.minecraft.net/" + value.hash.substr(0, 2) + '/' + value.hash;
        if (check_local_file(Object, value.size, value.hash)) continue;
        ++fileCount;
        totalSize += value.size;
        downloader.AddTask(url, Object, value.size, value.hash);
    }
    if (!vd.logging.client.file.id.empty() && !vd.logging.client.file.url.empty()) {
        fs::path Logging = fs::path(".minecraft/assets/log_configs") / vd.logging.client.file.id;
        fs::create_directories(Logging.parent_path());
        if (!check_local_file(Logging, vd.logging.client.file.size, vd.logging.client.file.sha1)) {
            ++fileCount;
            totalSize += vd.logging.client.file.size;
            downloader.AddTask(vd.logging.client.file.url, Logging,
                    vd.logging.client.file.size, vd.logging.client.file.sha1);
        }
    }
    std::cout << "已发现 " << fileCount << " 个文件，总大小 " << formatBytes(totalSize) << "\n" << std::endl; 

    downloader.SetCallback(report_download_progress, &totalSize);
    downloader.Perform();
    std::cout << "\n下载完成！";
}

int main(int argc, char* argv[]) {
    int exit_code = 0;
    try {
        run(argc, argv);
    } catch (const std::exception& e) {
        print_exception(e);       // 前面那个带类型名的递归打印
        exit_code = 1;
    } catch (...) {
        std::cerr << "-> (unknown non-std exception)\n";
        exit_code = 2;
    }
    std::cout << "按回车键退出……" << std::endl;
    std::cin.get();
    return exit_code;
}

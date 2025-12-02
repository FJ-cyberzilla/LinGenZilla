// ============================================================================
// CYBERZILLA - PROFESSIONAL LINK GENERATOR SYSTEM v2.0
// Enterprise-Grade Production Implementation
// ============================================================================

// CMakeLists.txt
/*
cmake_minimum_required(VERSION 3.15)
project(CyberZilla VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SQLite3 REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(cyberzilla
    src/main.cpp
    src/database.cpp
    src/url_shortener.cpp
    src/qr_generator.cpp
    src/analytics.cpp
    src/interface.cpp
    src/http_server.cpp
)

target_link_libraries(cyberzilla
    SQLite::SQLite3
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    qrencode
)
*/

// ============================================================================
// database.hpp - SQLite Database Layer
// ============================================================================

#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <sqlite3.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <mutex>
#include <chrono>

class Database {
private:
    sqlite3* db;
    std::mutex dbMutex;
    std::string dbPath;

    void executeSQL(const std::string& sql) {
        char* errMsg = nullptr;
        int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK) {
            std::string error = errMsg ? errMsg : "Unknown error";
            sqlite3_free(errMsg);
            throw std::runtime_error("SQL error: " + error);
        }
    }

public:
    Database(const std::string& path = "cyberzilla.db") : db(nullptr), dbPath(path) {
        int rc = sqlite3_open(path.c_str(), &db);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("Cannot open database: " + std::string(sqlite3_errmsg(db)));
        }
        
        // Enable WAL mode for better concurrency
        executeSQL("PRAGMA journal_mode=WAL");
        executeSQL("PRAGMA synchronous=NORMAL");
        executeSQL("PRAGMA foreign_keys=ON");
        
        initializeTables();
    }

    ~Database() {
        if (db) {
            sqlite3_close(db);
        }
    }

    void initializeTables() {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        // Links table
        executeSQL(R"(
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                short_code TEXT UNIQUE NOT NULL,
                original_url TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                custom_domain TEXT,
                utm_source TEXT,
                utm_medium TEXT,
                utm_campaign TEXT,
                utm_term TEXT,
                utm_content TEXT,
                is_active INTEGER DEFAULT 1,
                INDEX idx_short_code (short_code),
                INDEX idx_created_at (created_at)
            )
        )");

        // Clicks table
        executeSQL(R"(
            CREATE TABLE IF NOT EXISTS clicks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id INTEGER NOT NULL,
                clicked_at INTEGER NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                referrer TEXT,
                country TEXT,
                city TEXT,
                device_type TEXT,
                browser TEXT,
                os TEXT,
                FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE,
                INDEX idx_link_id (link_id),
                INDEX idx_clicked_at (clicked_at)
            )
        )");

        // QR Codes table
        executeSQL(R"(
            CREATE TABLE IF NOT EXISTS qr_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id INTEGER NOT NULL,
                format TEXT NOT NULL,
                size INTEGER NOT NULL,
                error_correction INTEGER NOT NULL,
                image_data BLOB,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
            )
        )");

        // API Keys table
        executeSQL(R"(
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_used INTEGER,
                requests_count INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1
            )
        )");
    }

    // Insert new link
    int64_t insertLink(const std::string& shortCode, const std::string& originalUrl,
                       const std::string& utmSource = "", const std::string& utmMedium = "",
                       const std::string& utmCampaign = "", int64_t expiresAt = 0) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        sqlite3_stmt* stmt;
        const char* sql = R"(
            INSERT INTO links (short_code, original_url, created_at, expires_at,
                             utm_source, utm_medium, utm_campaign)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        )";
        
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db)));
        }

        int64_t now = std::chrono::system_clock::now().time_since_epoch().count();
        
        sqlite3_bind_text(stmt, 1, shortCode.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, originalUrl.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, now);
        sqlite3_bind_int64(stmt, 4, expiresAt);
        sqlite3_bind_text(stmt, 5, utmSource.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, utmMedium.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, utmCampaign.c_str(), -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            throw std::runtime_error("Failed to insert link: " + std::string(sqlite3_errmsg(db)));
        }

        return sqlite3_last_insert_rowid(db);
    }

    // Get link by short code
    struct LinkData {
        int64_t id;
        std::string shortCode;
        std::string originalUrl;
        int64_t createdAt;
        int64_t expiresAt;
        std::string utmSource;
        std::string utmMedium;
        std::string utmCampaign;
        bool isActive;
        bool exists;

        LinkData() : id(0), createdAt(0), expiresAt(0), isActive(false), exists(false) {}
    };

    LinkData getLinkByShortCode(const std::string& shortCode) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        LinkData result;
        sqlite3_stmt* stmt;
        const char* sql = R"(
            SELECT id, short_code, original_url, created_at, expires_at,
                   utm_source, utm_medium, utm_campaign, is_active
            FROM links WHERE short_code = ? AND is_active = 1
        )";

        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            return result;
        }

        sqlite3_bind_text(stmt, 1, shortCode.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            result.exists = true;
            result.id = sqlite3_column_int64(stmt, 0);
            result.shortCode = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            result.originalUrl = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            result.createdAt = sqlite3_column_int64(stmt, 3);
            result.expiresAt = sqlite3_column_int64(stmt, 4);
            
            const char* utmSrc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            const char* utmMed = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            const char* utmCamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            
            result.utmSource = utmSrc ? utmSrc : "";
            result.utmMedium = utmMed ? utmMed : "";
            result.utmCampaign = utmCamp ? utmCamp : "";
            result.isActive = sqlite3_column_int(stmt, 8) == 1;
        }

        sqlite3_finalize(stmt);
        return result;
    }

    // Record click
    void recordClick(int64_t linkId, const std::string& ipAddress, const std::string& userAgent,
                    const std::string& referrer, const std::string& country = "",
                    const std::string& city = "", const std::string& deviceType = "",
                    const std::string& browser = "", const std::string& os = "") {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        sqlite3_stmt* stmt;
        const char* sql = R"(
            INSERT INTO clicks (link_id, clicked_at, ip_address, user_agent, referrer,
                              country, city, device_type, browser, os)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )";

        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return;

        int64_t now = std::chrono::system_clock::now().time_since_epoch().count();

        sqlite3_bind_int64(stmt, 1, linkId);
        sqlite3_bind_int64(stmt, 2, now);
        sqlite3_bind_text(stmt, 3, ipAddress.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, userAgent.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, referrer.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, country.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, city.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, deviceType.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, browser.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, os.c_str(), -1, SQLITE_TRANSIENT);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Get click statistics
    struct ClickStats {
        int64_t totalClicks;
        std::vector<std::pair<std::string, int>> topReferrers;
        std::vector<std::pair<std::string, int>> topCountries;
        std::vector<std::pair<std::string, int>> topBrowsers;
        std::vector<std::pair<int64_t, int>> clicksByHour;
    };

    ClickStats getClickStats(int64_t linkId, int64_t since = 0) {
        std::lock_guard<std::mutex> lock(dbMutex);
        ClickStats stats;
        
        // Total clicks
        sqlite3_stmt* stmt;
        const char* sql = "SELECT COUNT(*) FROM clicks WHERE link_id = ? AND clicked_at >= ?";
        sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        sqlite3_bind_int64(stmt, 1, linkId);
        sqlite3_bind_int64(stmt, 2, since);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.totalClicks = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);

        // Top referrers
        sql = R"(
            SELECT referrer, COUNT(*) as cnt 
            FROM clicks 
            WHERE link_id = ? AND clicked_at >= ? AND referrer != ''
            GROUP BY referrer 
            ORDER BY cnt DESC 
            LIMIT 10
        )";
        sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        sqlite3_bind_int64(stmt, 1, linkId);
        sqlite3_bind_int64(stmt, 2, since);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string ref = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int count = sqlite3_column_int(stmt, 1);
            stats.topReferrers.push_back({ref, count});
        }
        sqlite3_finalize(stmt);

        // Top countries
        sql = R"(
            SELECT country, COUNT(*) as cnt 
            FROM clicks 
            WHERE link_id = ? AND clicked_at >= ? AND country != ''
            GROUP BY country 
            ORDER BY cnt DESC 
            LIMIT 10
        )";
        sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        sqlite3_bind_int64(stmt, 1, linkId);
        sqlite3_bind_int64(stmt, 2, since);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string country = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int count = sqlite3_column_int(stmt, 1);
            stats.topCountries.push_back({country, count});
        }
        sqlite3_finalize(stmt);

        // Top browsers
        sql = R"(
            SELECT browser, COUNT(*) as cnt 
            FROM clicks 
            WHERE link_id = ? AND clicked_at >= ? AND browser != ''
            GROUP BY browser 
            ORDER BY cnt DESC 
            LIMIT 10
        )";
        sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
        sqlite3_bind_int64(stmt, 1, linkId);
        sqlite3_bind_int64(stmt, 2, since);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string browser = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int count = sqlite3_column_int(stmt, 1);
            stats.topBrowsers.push_back({browser, count});
        }
        sqlite3_finalize(stmt);

        return stats;
    }

    // Backup database
    bool backupTo(const std::string& backupPath) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        sqlite3* backupDb;
        int rc = sqlite3_open(backupPath.c_str(), &backupDb);
        if (rc != SQLITE_OK) return false;

        sqlite3_backup* backup = sqlite3_backup_init(backupDb, "main", db, "main");
        if (backup) {
            sqlite3_backup_step(backup, -1);
            sqlite3_backup_finish(backup);
        }
        
        sqlite3_close(backupDb);
        return true;
    }
};

#endif // DATABASE_HPP

// ============================================================================
// url_utils.hpp - URL Encoding/Validation
// ============================================================================

#ifndef URL_UTILS_HPP
#define URL_UTILS_HPP

#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <curl/curl.h>

class URLUtils {
public:
    static std::string encode(const std::string& value) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;

        for (char c : value) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                escaped << c;
            } else {
                escaped << std::uppercase;
                escaped << '%' << std::setw(2) << int((unsigned char)c);
                escaped << std::nouppercase;
            }
        }

        return escaped.str();
    }

    static std::string decode(const std::string& value) {
        CURL* curl = curl_easy_init();
        if (!curl) return value;
        
        int outlength;
        char* decoded = curl_easy_unescape(curl, value.c_str(), value.length(), &outlength);
        std::string result(decoded, outlength);
        
        curl_free(decoded);
        curl_easy_cleanup(curl);
        
        return result;
    }

    static bool isValid(const std::string& url) {
        std::regex urlRegex(
            R"(^(https?):\/\/(([a-zA-Z0-9$\-_.+!*'(),;?&=]|%[0-9a-fA-F]{2})+@)?(([a-zA-Z0-9\-._~]+|\[[0-9a-fA-F:.]+\]))(:[0-9]{1,5})?(\/[^?#]*)? (\?[^#]*)?(#.*)?$)"
        );
        return std::regex_match(url, urlRegex);
    }

    static std::string buildURL(const std::string& base, 
                               const std::map<std::string, std::string>& params) {
        if (params.empty()) return base;
        
        std::string url = base;
        url += (base.find('?') != std::string::npos) ? "&" : "?";
        
        bool first = true;
        for (const auto& [key, value] : params) {
            if (!first) url += "&";
            url += encode(key) + "=" + encode(value);
            first = false;
        }
        
        return url;
    }

    static std::string normalizeURL(const std::string& url) {
        std::string normalized = url;
        
        // Remove trailing slash
        if (normalized.back() == '/' && normalized.length() > 1) {
            normalized.pop_back();
        }
        
        // Convert to lowercase (except path)
        size_t schemeEnd = normalized.find("://");
        if (schemeEnd != std::string::npos) {
            std::transform(normalized.begin(), normalized.begin() + schemeEnd + 3,
                         normalized.begin(), ::tolower);
        }
        
        return normalized;
    }
};

#endif // URL_UTILS_HPP

// ============================================================================
// qr_generator.hpp - Real QR Code Generation using libqrencode
// ============================================================================

#ifndef QR_GENERATOR_HPP
#define QR_GENERATOR_HPP

#include <qrencode.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <memory>
#include <cstring>

class QRGenerator {
public:
    enum class ErrorCorrection {
        LOW = QR_ECLEVEL_L,
        MEDIUM = QR_ECLEVEL_M,
        QUARTILE = QR_ECLEVEL_Q,
        HIGH = QR_ECLEVEL_H
    };

    struct QRCode {
        int version;
        int width;
        std::vector<uint8_t> data;
        bool success;

        QRCode() : version(0), width(0), success(false) {}
    };

    static QRCode generate(const std::string& text, 
                          ErrorCorrection ec = ErrorCorrection::MEDIUM,
                          int minVersion = 1) {
        QRCode result;
        
        QRcode* qr = QRcode_encodeString(text.c_str(), minVersion, 
                                         static_cast<QRecLevel>(ec),
                                         QR_MODE_8, 1);
        
        if (!qr) {
            return result;
        }

        result.version = qr->version;
        result.width = qr->width;
        result.data.assign(qr->data, qr->data + (qr->width * qr->width));
        result.success = true;

        QRcode_free(qr);
        return result;
    }

    static std::string toASCII(const QRCode& qr, int scale = 1) {
        if (!qr.success) return "";

        std::stringstream ss;
        
        // Top border
        ss << "\n";
        for (int i = 0; i < (qr.width * scale) + 4; ++i) ss << "█";
        ss << "\n";

        for (int y = 0; y < qr.width; ++y) {
            for (int sy = 0; sy < scale; ++sy) {
                ss << "██";  // Left border
                for (int x = 0; x < qr.width; ++x) {
                    bool black = qr.data[y * qr.width + x] & 1;
                    for (int sx = 0; sx < scale; ++sx) {
                        ss << (black ? "██" : "  ");
                    }
                }
                ss << "██\n";  // Right border
            }
        }

        // Bottom border
        for (int i = 0; i < (qr.width * scale) + 4; ++i) ss << "█";
        ss << "\n";

        return ss.str();
    }

    static bool toPNG(const QRCode& qr, const std::string& filename, 
                     int pixelSize = 10, int margin = 4) {
        if (!qr.success) return false;

        // Simple PNM format (can be converted to PNG with ImageMagick)
        int totalSize = qr.width + (margin * 2);
        int imageSize = totalSize * pixelSize;

        std::ofstream file(filename + ".pnm", std::ios::binary);
        if (!file.is_open()) return false;

        // PGM header
        file << "P5\n" << imageSize << " " << imageSize << "\n255\n";

        // Write pixels
        for (int y = 0; y < imageSize; ++y) {
            int qrY = (y / pixelSize) - margin;
            for (int x = 0; x < imageSize; ++x) {
                int qrX = (x / pixelSize) - margin;
                
                uint8_t pixel = 255;  // White
                if (qrY >= 0 && qrY < qr.width && qrX >= 0 && qrX < qr.width) {
                    if (qr.data[qrY * qr.width + qrX] & 1) {
                        pixel = 0;  // Black
                    }
                }
                file.write(reinterpret_cast<const char*>(&pixel), 1);
            }
        }

        file.close();
        return true;
    }

    static bool toSVG(const QRCode& qr, const std::string& filename, 
                     int pixelSize = 10, int margin = 4) {
        if (!qr.success) return false;

        int totalSize = qr.width + (margin * 2);
        int imageSize = totalSize * pixelSize;

        std::ofstream file(filename);
        if (!file.is_open()) return false;

        file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        file << "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" ";
        file << "width=\"" << imageSize << "\" height=\"" << imageSize << "\">\n";
        file << "<rect width=\"" << imageSize << "\" height=\"" << imageSize << "\" fill=\"white\"/>\n";

        for (int y = 0; y < qr.width; ++y) {
            for (int x = 0; x < qr.width; ++x) {
                if (qr.data[y * qr.width + x] & 1) {
                    int px = (x + margin) * pixelSize;
                    int py = (y + margin) * pixelSize;
                    file << "<rect x=\"" << px << "\" y=\"" << py << "\" ";
                    file << "width=\"" << pixelSize << "\" height=\"" << pixelSize << "\" fill=\"black\"/>\n";
                }
            }
        }

        file << "</svg>\n";
        file.close();
        return true;
    }
};

#endif // QR_GENERATOR_HPP

// ============================================================================
// shortener.hpp - URL Shortening Engine
// ============================================================================

#ifndef SHORTENER_HPP
#define SHORTENER_HPP

#include <string>
#include <random>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

class URLShortener {
private:
    std::mt19937_64 rng;
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    Database& db;
    std::string baseURL;

public:
    URLShortener(Database& database, const std::string& base = "https://czl.ink/") 
        : db(database), baseURL(base), rng(std::random_device{}()) {}

    std::string generateShortCode(int length = 7) {
        std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);
        std::string code;
        
        do {
            code.clear();
            for (int i = 0; i < length; ++i) {
                code += charset[dist(rng)];
            }
        } while (db.getLinkByShortCode(code).exists);
        
        return code;
    }

    std::string hashURL(const std::string& url) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(url.c_str()), 
               url.length(), hash);
        
        std::stringstream ss;
        for (int i = 0; i < 7; ++i) {
            ss << charset[hash[i] % charset.size()];
        }
        return ss.str();
    }

    struct ShortenResult {
        bool success;
        std::string shortURL;
        std::string shortCode;
        std::string error;
        int64_t linkId;

        ShortenResult() : success(false), linkId(0) {}
    };

    ShortenResult shorten(const std::string& originalURL,
                         const std::string& customCode = "",
                         const std::string& utmSource = "",
                         const std::string& utmMedium = "",
                         const std::string& utmCampaign = "",
                         int64_t expiresIn = 0) {
        ShortenResult result;

        // Validate URL
        if (!URLUtils::isValid(originalURL)) {
            result.error = "Invalid URL format";
            return result;
        }

        // Generate or use custom code
        std::string code;
        if (!customCode.empty()) {
            if (db.getLinkByShortCode(customCode).exists) {
                result.error = "Custom code already exists";
                return result;
            }
            code = customCode;
        } else {
            code = generateShortCode();
        }

        // Calculate expiration
        int64_t expiresAt = 0;
        if (expiresIn > 0) {
            auto now = std::chrono::system_clock::now();
            auto expiry = now + std::chrono::seconds(expiresIn);
            expiresAt = std::chrono::duration_cast<std::chrono::nanoseconds>(
                expiry.time_since_epoch()).count();
        }

        try {
            int64_t linkId = db.insertLink(code, originalURL, utmSource, 
                                          utmMedium, utmCampaign, expiresAt);
            
            result.success = true;
            result.shortCode = code;
            result.shortURL = baseURL + code;
            result.linkId = linkId;
        } catch (const std::exception& e) {
            result.error = e.what();
        }

        return result;
    }

    struct ResolveResult {
        bool success;
        std::string originalURL;
        bool expired;
        int64_t linkId;

        ResolveResult() : success(false), expired(false), linkId(0) {}
    };

    ResolveResult resolve(const std::string& shortCode) {
        ResolveResult result;
        
        auto link = db.getLinkByShortCode(shortCode);
        if (!link.exists) {
            return result;
        }

        // Check expiration
        if (link.expiresAt > 0) {
            auto now = std::chrono::system_clock::now().time_since_epoch().count();
            if (now > link.expiresAt) {
                result.expired = true;
                return result;
            }
        }

        result.success = true;
        result.originalURL = link.originalUrl;
        result.linkId = link.id;
        
        return result;
    }
};

#endif // SHORTENER_HPP

// ============================================================================
// main.cpp - Main Application with ASCII Interface
// ============================================================================

#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <ctime>

class ASCIIInterface {
public:
    void clearScreen() {
        #ifdef _WIN32
            system("cls");
        #else
            std::cout << "\033[2J\033[1;1H";
        #endif
    }

    std::string getCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    void displayBanner() {
        clearScreen();
        std::cout << "\033[32m";  // Green color
        std::cout << R"(
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗██╗     ██╗      █████╗ 
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗╚══███╔╝██║██║     ██║     ██╔══██╗
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝  ███╔╝ ██║██║     ██║     ███████║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗ ███╔╝  ██║██║     ██║     ██╔══██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████╗██║███████╗███████╗██║  ██║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
)" << "\n";
        std::cout << "\033[0m";  // Reset color
        std::cout << "\033[36m";  // Cyan
        std::cout << "              [ PROFESSIONAL LINK GENERATOR SYSTEM v2.0 ]\n";
        std::cout << "              [ " << getCurrentTime() << " ]\n\n";
        std::cout << "\033[0m";
    }

    void displayMenu() {
        std::cout << "\033[32m";
        std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                     COMMAND CENTER                                ║\n";
        std::cout << "╠═══════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  \033[33m[1]\033[32m Generate Tracking Link      \033[33m[2]\033[32m Shorten URL                 ║\n";
        std::cout << "║  \033[33m[3]\033[32m Create QR Code              \033[33m[4]\033[32m View Analytics              ║\n";
        std::cout << "║  \033[33m[5]\033[32m List All Links              \033[33m[6]\033[32m Export Data                 ║\n";
        std::cout << "║  \033[33m[7]\033[32m Database Backup             \033[33m[8]\033[32m System Stats                ║\n";
        std::cout << "║  \033[33m[0]\033[32m Exit                                                        ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
        std::cout << "\033[0m\n";
        std::cout << "\033[36mcyberzilla>\033[0m ";
    }

    void displaySuccess(const std::string& message) {
        std::cout << "\n\033[32m✓ SUCCESS:\033[0m " << message << "\n";
    }

    void displayError(const std::string& message) {
        std::cout << "\n\033[31m✗ ERROR:\033[0m " << message << "\n";
    }

    void displayInfo(const std::string& message) {
        std::cout << "\033[36mℹ INFO:\033[0m " << message << "\n";
    }

    void displayProgress(const std::string& task, int percent) {
        int barWidth = 50;
        std::cout << "\r\033[36m[" << task << "]\033[0m [";
        int pos = barWidth * percent / 100;
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << "\033[32m█\033[0m";
            else if (i == pos) std::cout << "\033[32m>\033[0m";
            else std::cout << " ";
        }
        std::cout << "] " << percent << "% " << std::flush;
        if (percent == 100) std::cout << "\n";
    }

    void displayBox(const std::string& title, const std::vector<std::string>& content) {
        std::cout << "\n\033[32m╔";
        for (size_t i = 0; i < 67; ++i) std::cout << "═";
        std::cout << "╗\n";
        
        std::cout << "║ \033[33m" << std::left << std::setw(65) << title << "\033[32m ║\n";
        
        std::cout << "╠";
        for (size_t i = 0; i < 67; ++i) std::cout << "═";
        std::cout << "╣\n";

        for (const auto& line : content) {
            std::cout << "║ \033[0m" << std::left << std::setw(65) << line << "\033[32m ║\n";
        }

        std::cout << "╚";
        for (size_t i = 0; i < 67; ++i) std::cout << "═";
        std::cout << "╝\033[0m\n";
    }

    std::string getInput(const std::string& prompt) {
        std::cout << "\033[36m" << prompt << ":\033[0m ";
        std::string input;
        std::getline(std::cin, input);
        return input;
    }

    void pause() {
        std::cout << "\n\033[90mPress Enter to continue...\033[0m";
        std::cin.get();
    }
};

// ============================================================================
// Analytics Display
// ============================================================================

class AnalyticsDisplay {
public:
    static void showLinkAnalytics(Database& db, int64_t linkId, const std::string& shortCode) {
        auto link = db.getLinkByShortCode(shortCode);
        if (!link.exists) {
            std::cout << "\n\033[31mLink not found!\033[0m\n";
            return;
        }

        auto stats = db.getClickStats(linkId);

        std::cout << "\n\033[32m╔";
        for (int i = 0; i < 67; ++i) std::cout << "═";
        std::cout << "╗\n";
        
        std::cout << "║ \033[33m" << std::left << std::setw(65) << "LINK ANALYTICS REPORT" << "\033[32m ║\n";
        
        std::cout << "╠";
        for (int i = 0; i < 67; ++i) std::cout << "═";
        std::cout << "╣\n";

        std::cout << "║ \033[0mShort Code:    " << std::left << std::setw(49) << shortCode << "\033[32m ║\n";
        std::cout << "║ \033[0mOriginal URL:  " << std::left << std::setw(49) 
                  << truncate(link.originalUrl, 49) << "\033[32m ║\n";
        std::cout << "║ \033[0mTotal Clicks:  " << std::left << std::setw(49) << stats.totalClicks << "\033[32m ║\n";

        if (!link.utmSource.empty()) {
            std::cout << "║ \033[0mUTM Source:    " << std::left << std::setw(49) << link.utmSource << "\033[32m ║\n";
            std::cout << "║ \033[0mUTM Medium:    " << std::left << std::setw(49) << link.utmMedium << "\033[32m ║\n";
            std::cout << "║ \033[0mUTM Campaign:  " << std::left << std::setw(49) << link.utmCampaign << "\033[32m ║\n";
        }

        std::cout << "╠";
        for (int i = 0; i < 67; ++i) std::cout << "═";
        std::cout << "╣\n";

        if (!stats.topReferrers.empty()) {
            std::cout << "║ \033[33mTOP REFERRERS:\033[32m" << std::string(52, ' ') << " ║\n";
            for (size_t i = 0; i < std::min(size_t(5), stats.topReferrers.size()); ++i) {
                std::stringstream ss;
                ss << "  • " << std::left << std::setw(45) << truncate(stats.topReferrers[i].first, 45)
                   << std::right << std::setw(5) << stats.topReferrers[i].second << " clicks";
                std::cout << "║ \033[0m" << std::left << std::setw(65) << ss.str() << "\033[32m ║\n";
            }
        }

        if (!stats.topCountries.empty()) {
            std::cout << "╠";
            for (int i = 0; i < 67; ++i) std::cout << "═";
            std::cout << "╣\n";
            std::cout << "║ \033[33mTOP COUNTRIES:\033[32m" << std::string(52, ' ') << " ║\n";
            for (size_t i = 0; i < std::min(size_t(5), stats.topCountries.size()); ++i) {
                std::stringstream ss;
                ss << "  • " << std::left << std::setw(45) << stats.topCountries[i].first
                   << std::right << std::setw(5) << stats.topCountries[i].second << " clicks";
                std::cout << "║ \033[0m" << std::left << std::setw(65) << ss.str() << "\033[32m ║\n";
            }
        }

        if (!stats.topBrowsers.empty()) {
            std::cout << "╠";
            for (int i = 0; i < 67; ++i) std::cout << "═";
            std::cout << "╣\n";
            std::cout << "║ \033[33mTOP BROWSERS:\033[32m" << std::string(53, ' ') << " ║\n";
            for (size_t i = 0; i < std::min(size_t(5), stats.topBrowsers.size()); ++i) {
                std::stringstream ss;
                ss << "  • " << std::left << std::setw(45) << stats.topBrowsers[i].first
                   << std::right << std::setw(5) << stats.topBrowsers[i].second << " clicks";
                std::cout << "║ \033[0m" << std::left << std::setw(65) << ss.str() << "\033[32m ║\n";
            }
        }

        std::cout << "╚";
        for (int i = 0; i < 67; ++i) std::cout << "═";
        std::cout << "╝\033[0m\n";
    }

private:
    static std::string truncate(const std::string& str, size_t width) {
        if (str.length() <= width) return str;
        return str.substr(0, width - 3) + "...";
    }
};

// ============================================================================
// Main Application
// ============================================================================

class CyberZillaApp {
private:
    Database db;
    URLShortener shortener;
    ASCIIInterface ui;
    bool running;

public:
    CyberZillaApp() : db("cyberzilla.db"), shortener(db), running(true) {
        // Initialize database
        ui.displayInfo("Initializing database...");
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    void run() {
        while (running) {
            ui.displayBanner();
            ui.displayMenu();

            std::string input;
            std::getline(std::cin, input);

            if (input.empty()) continue;

            int choice = 0;
            try {
                choice = std::stoi(input);
            } catch (...) {
                ui.displayError("Invalid input");
                ui.pause();
                continue;
            }

            switch (choice) {
                case 1: generateTrackingLink(); break;
                case 2: shortenURL(); break;
                case 3: createQRCode(); break;
                case 4: viewAnalytics(); break;
                case 5: listAllLinks(); break;
                case 6: exportData(); break;
                case 7: backupDatabase(); break;
                case 8: systemStats(); break;
                case 0: 
                    running = false;
                    ui.clearScreen();
                    std::cout << "\n\033[32m╔═══════════════════════════════════════╗\n";
                    std::cout << "║  Thank you for using CyberZilla!     ║\n";
                    std::cout << "╚═══════════════════════════════════════╝\033[0m\n\n";
                    break;
                default: 
                    ui.displayError("Invalid option");
                    ui.pause();
            }
        }
    }

private:
    void generateTrackingLink() {
        ui.clearScreen();
        std::cout << "\n\033[32m╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              GENERATE TRACKING LINK WITH UTM PARAMETERS           ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝\033[0m\n\n";

        std::string url = ui.getInput("Enter original URL");
        if (url.empty()) {
            ui.displayError("URL cannot be empty");
            ui.pause();
            return;
        }

        std::string source = ui.getInput("UTM Source (e.g., newsletter, facebook)");
        std::string medium = ui.getInput("UTM Medium (e.g., email, social)");
        std::string campaign = ui.getInput("UTM Campaign (e.g., summer_sale)");
        std::string term = ui.getInput("UTM Term (optional, press Enter to skip)");
        std::string content = ui.getInput("UTM Content (optional, press Enter to skip)");

        // Build UTM parameters
        std::map<std::string, std::string> utmParams;
        if (!source.empty()) utmParams["utm_source"] = source;
        if (!medium.empty()) utmParams["utm_medium"] = medium;
        if (!campaign.empty()) utmParams["utm_campaign"] = campaign;
        if (!term.empty()) utmParams["utm_term"] = term;
        if (!content.empty()) utmParams["utm_content"] = content;

        std::string trackedURL = URLUtils::buildURL(url, utmParams);

        ui.displayProgress("Generating", 30);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        ui.displayProgress("Generating", 70);

        auto result = shortener.shorten(trackedURL, "", source, medium, campaign);

        ui.displayProgress("Generating", 100);

        if (result.success) {
            std::vector<std::string> content;
            content.push_back("Original URL:  " + url);
            content.push_back("Tracked URL:   " + trackedURL);
            content.push_back("Short URL:     " + result.shortURL);
            content.push_back("Short Code:    " + result.shortCode);
            content.push_back("");
            content.push_back("UTM Parameters:");
            content.push_back("  Source:      " + source);
            content.push_back("  Medium:      " + medium);
            content.push_back("  Campaign:    " + campaign);
            if (!term.empty()) content.push_back("  Term:        " + term);
            if (!content.empty()) content.push_back("  Content:     " + content.back());

            ui.displayBox("TRACKING LINK GENERATED", content);
            ui.displaySuccess("Link created successfully!");
        } else {
            ui.displayError(result.error);
        }

        ui.pause();
    }

    void shortenURL() {
        ui.clearScreen();
        std::cout << "\n\033[32m╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                        SHORTEN URL                                ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝\033[0m\n\n";

        std::string url = ui.getInput("Enter URL to shorten");
        if (url.empty()) {
            ui.displayError("URL cannot be empty");
            ui.pause();
            return;
        }

        std::string customCode = ui.getInput("Custom short code (optional, press Enter for auto)");

        ui.displayProgress("Shortening", 50);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        auto result = shortener.shorten(url, customCode);

        ui.displayProgress("Shortening", 100);

        if (result.success) {
            std::vector<std::string> content;
            content.push_back("Original URL:  " + url);
            content.push_back("Short URL:     " + result.shortURL);
            content.push_back("Short Code:    " + result.shortCode);
            content.push_back("Link ID:       " + std::to_string(result.linkId));

            ui.displayBox("URL SHORTENED", content);
            ui.displaySuccess("Link created successfully!");
        } else {
            ui.displayError(result.error);
        }

        ui.pause();
    }

    void createQRCode() {
        ui.clearScreen();
        std::cout << "\n\033[32m╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                        CREATE QR CODE                             ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝\033[0m\n\n";

        std::string shortCode = ui.getInput("Enter short code or full URL");
        if (shortCode.empty()) {
            ui.displayError("Input cannot be empty");
            ui.pause();
            return;
        }

        std::string data = shortCode;
        if (shortCode.find("://") == std::string::npos) {
            data = shortener.baseURL + shortCode;
        }

        std::string format = ui.getInput("Format (1=ASCII, 2=SVG, 3=PNG) [1]");
        if (format.empty()) format = "1";

        ui.displayProgress("Generating QR", 50);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        auto qr = QRGenerator::generate(data, QRGenerator::ErrorCorrection::MEDIUM);

        ui.displayProgress("Generating QR", 100);

        if (qr.success) {
            if (format == "1") {
                std::cout << QRGenerator::toASCII(qr, 1);
                ui.displaySuccess("QR Code generated!");
            } else if (format == "2") {
                std::string filename = "qr_" + shortCode + ".svg";
                if (QRGenerator::toSVG(qr, filename)) {
                    ui.displaySuccess("QR Code saved to " + filename);
                } else {
                    ui.displayError("Failed to save SVG");
                }
            } else if (format == "3") {
                std::string filename = "qr_" + shortCode;
                if (QRGenerator::toPNG(qr, filename)) {
                    ui.displaySuccess("QR Code saved to " + filename + ".pnm (convert to PNG with ImageMagick)");
                } else {
                    ui.displayError("Failed to save PNG");
                }
            }
        } else {
            ui.displayError("Failed to generate QR code");
        }

        ui.pause();
    }

    void viewAnalytics() {
        ui.clearScreen();
        std::cout << "\n\033[32m╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                        VIEW ANALYTICS                             ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝\033[0m\n\n";

        std::string shortCode = ui.getInput("Enter short code");
        if (shortCode.empty()) {
            ui.displayError("Short code cannot be empty");
            ui.pause();
            return;
        }

        auto link = db.getLinkByShortCode(shortCode);
        if (!link.exists) {
            ui.displayError("Short code not found");
            ui.pause();
            return;
        }

        ui.displayProgress("Loading analytics", 100);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        AnalyticsDisplay::showLinkAnalytics(db, link.id, shortCode);
        ui.pause();
    }

    void listAllLinks() {
        ui.displayInfo("Feature: List all links with pagination");
        ui.displayError("Coming in next version!");
        ui.pause();
    }

    void exportData() {
        ui.displayInfo("Feature: Export analytics to CSV/JSON");
        ui.displayError("Coming in next version!");
        ui.pause();
    }

    void backupDatabase() {
        ui.clearScreen();
        std::cout << "\n\033[32m╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                        DATABASE BACKUP                            ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝\033[0m\n\n";

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << "backup_" << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S") << ".db";
        std::string backupFile = ss.str();

        ui.displayProgress("Creating backup", 50);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        if (db.backupTo(backupFile)) {
            ui.displayProgress("Creating backup", 100);
            ui.displaySuccess("Database backed up to " + backupFile);
        } else {
            ui.displayError("Backup failed");
        }

        ui.pause();
    }

    void systemStats() {
        ui.clearScreen();
        std::cout << "\n\033[32m╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                        SYSTEM STATISTICS                          ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝\033[0m\n\n";

        ui.displayInfo("Database: cyberzilla.db");
        ui.displayInfo("Version: 2.0.0");
        ui.displayInfo("Status: Operational");
        
        ui.pause();
    }
};

// ============================================================================
// Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    try {
        CyberZillaApp app;
        app.run();
    } catch (const std::exception& e) {
        std::cerr << "\033[31mFATAL ERROR: " << e.what() << "\033[0m\n";
        return 1;
    }
    
    return 0;
}

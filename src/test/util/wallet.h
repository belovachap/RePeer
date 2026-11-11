#ifndef TEST_UTIL_WALLET_H
#define TEST_UTIL_WALLET_H

#include <wallet/db.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace wallet {

class MockableDatabase : public WalletDatabase
{
public:
    MockableDatabase() = default;
    ~MockableDatabase() override = default;

    void Open() override {}
    void Flush() override {}
    void Close() override {}
    void AddRef() override {}
    void RemoveRef() override {}
    bool Rewrite(const char* pszSkip = nullptr) override { return true; }
    bool Backup(const std::string& strDest) const override { return true; }
    bool PeriodicFlush() override { return true; }
    void IncrementUpdateCounter() override { ++nUpdateCounter; }
    void ReloadDbEnv() override {}
    std::string Filename() override { return "mockable"; }
    std::string Format() override { return "mockable"; }

    std::unique_ptr<DatabaseBatch> MakeBatch(bool flush_on_close = true) override
    {
        return std::make_unique<MockableBatch>(*this, flush_on_close);
    }

    std::map<std::string, std::string> m_database;

private:
    class MockableBatch : public DatabaseBatch
    {
        MockableDatabase& m_db;
        std::vector<std::pair<std::string, std::string>> m_batch;
        bool m_flush_on_close;
        bool m_closed = false;

    public:
        MockableBatch(MockableDatabase& db, bool flush_on_close = true)
            : m_db(db), m_flush_on_close(flush_on_close) {}

        ~MockableBatch() override
        {
            if (!m_closed && m_flush_on_close) {
                for (auto& [k, v] : m_batch) {
                    m_db.m_database[k] = v;
                }
            }
        }

        bool ReadKey(DataStream&& key, DataStream& value) override
        {
            std::string key_str;
            key >> key_str;
            auto it = m_db.m_database.find(key_str);
            if (it == m_db.m_database.end()) return false;
            value << it->second;
            return true;
        }

        bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite) override
        {
            std::string key_str;
            key >> key_str;
            std::string val_str;
            value >> val_str;
            if (!overwrite && m_db.m_database.count(key_str)) return false;
            m_batch.emplace_back(key_str, val_str);
            return true;
        }

        bool EraseKey(DataStream&& key) override
        {
            std::string key_str;
            key >> key_str;
            return m_db.m_database.erase(key_str) > 0;
        }

        bool HasKey(DataStream&& key) override
        {
            std::string key_str;
            key >> key_str;
            return m_db.m_database.count(key_str) > 0;
        }

        void Flush() override
        {
            for (auto& [k, v] : m_batch) {
                m_db.m_database[k] = v;
            }
            m_batch.clear();
        }

        void Close() override
        {
            if (!m_closed) {
                Flush();
                m_closed = true;
            }
        }

        std::unique_ptr<DatabaseCursor> GetNewCursor() override
        {
            return std::make_unique<MockableCursor>(m_db.m_database);
        }

        bool TxnBegin() override { return true; }
        bool TxnCommit() override { return true; }
        bool TxnAbort() override { return true; }
    };

    class MockableCursor : public DatabaseCursor
    {
        std::map<std::string, std::string>::const_iterator m_it;
        std::map<std::string, std::string>::const_iterator m_end;

    public:
        explicit MockableCursor(const std::map<std::string, std::string>& db)
            : m_it(db.begin()), m_end(db.end()) {}

        Status Next(DataStream& key, DataStream& value) override
        {
            if (m_it == m_end) return Status::DONE;
            key << m_it->first;
            value << m_it->second;
            ++m_it;
            return Status::MORE;
        }
    };
};

std::unique_ptr<WalletDatabase> CreateMockableWalletDatabase();

} // namespace wallet

#endif // TEST_UTIL_WALLET_H
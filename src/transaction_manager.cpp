#include "transaction_manager.h"

void TransactionManager::addTransaction(
    const Transaction& tx
)
{
    transactions_.push_back(tx);
}

std::vector<Transaction>&
TransactionManager::getTransactions()
{
    return transactions_;
}
bool TransactionManager::allowTransaction(
    const std::string& id
)
{
    for (auto& tx : transactions_)
    {
        if (tx.id == id)
        {
            tx.status = "ALLOWED";
            return true;
        }
    }

    return false;
}

bool TransactionManager::blockTransaction(
    const std::string& id
)
{
    for (auto& tx : transactions_)
    {
        if (tx.id == id)
        {
            tx.status = "BLOCKED";
            return true;
        }
    }

    return false;
}
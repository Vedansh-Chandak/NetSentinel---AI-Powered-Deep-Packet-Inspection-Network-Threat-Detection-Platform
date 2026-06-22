#pragma once

#include <vector>
#include <string>

#include "transaction.h"

class TransactionManager
{
public:

    void addTransaction(
        const Transaction& tx
    );

    std::vector<Transaction>&
    getTransactions();

    bool allowTransaction(
        const std::string& id
    );

    bool blockTransaction(
        const std::string& id
    );

private:

    std::vector<Transaction>
    transactions_;
};
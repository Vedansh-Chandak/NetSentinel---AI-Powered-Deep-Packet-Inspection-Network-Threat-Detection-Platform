#include "service_mapper.h"

std::string ServiceMapper::getService(
    uint16_t port)
{
    switch(port)
    {
        case 80:
            return "HTTP";

        case 443:
            return "HTTPS";

        case 53:
            return "DNS";

        case 22:
            return "SSH";

        case 21:
            return "FTP";

        case 25:
            return "SMTP";

        case 110:
            return "POP3";

        case 143:
            return "IMAP";

        case 3306:
            return "MySQL";

        case 5432:
            return "PostgreSQL";

        case 6379:
            return "Redis";

        case 27017:
            return "MongoDB";

        default:
            return "Unknown";
    }
}
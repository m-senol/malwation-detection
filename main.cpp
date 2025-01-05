#include "scan_memory.hpp"
#include <csignal>

ScanMemory *sm = nullptr; 

void interruption(int sig)
{
    (void) sig;
    delete sm;
    sm = nullptr;

    std::exit(0);
}

int main(int argc, char* argv[])
{
    if (std::signal(SIGINT, interruption) == SIG_ERR)
    {
        fprintf(stderr, "Signal Handler setup fail\n");
        return 1;
    }

    sm = new ScanMemory();
    if (sm->init(argc, argv) != 0)
    {
        delete sm;
        return 1;
    }
    
    if (sm->run() != 0)
    {
        delete sm;
        return 1;
    }

    delete sm;
    return 0;
}

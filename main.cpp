#include "scan_memory.hpp"

int main(int argc, char* argv[])
{
    ScanMemory sm;
    if (sm.init(argc, argv) != 0)
    {
        fprintf(stderr, "Error initiliasing the program\n");
        return 1;
    }
    
    if (sm.run() != 0)
    {
        return 1;
    }

    return 0;
}

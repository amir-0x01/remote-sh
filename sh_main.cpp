#include "shmain.hpp"

int main(int argc, char* argv[]){
    try{
        unsigned int PORT = atoi(argv[1]);
        mainsh socket_main;
    
        int* sock = socket_main.create_socket(PORT);
        socket_main.createsh();

    }

    catch(...){std::cout << "[-] error " << std::endl;}
    
    return 0;
}
// this header file contains all the neccessary functions and header files 
#ifndef UTILS
#define UTILS

#include <iostream>
#include <string.h>
#include <string>
#include <sys/time.h>
#include <thread>
#include <signal.h>
#include <vector>
#include <iterator>
#include <sstream>
#include <fstream>
#include <ctime>
#include <map>
#include <cstring>

//NETWORKING
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netdb.h>

std::string alphabet = "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
std::string str = "gjewklmzusnvqpycthrifxbdao DWKISFOGNUQZXBYCEVRLMAHPJT6547812390";

// used to split string
template<typename out>
void split(const std::string &s, char delim, out result) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

// this encryption method is designed to provide a basic layer of security against packet sniffing
// without encryption everyone could see the data sent (which includes password)
std::string ncrypt(std::string target){
    std::string encrypted;
    std::map <char, char> nmap;
    int pos = 0;

    for(char c : alphabet){
        nmap[c] = str.at(pos);
        pos++;
            
    }
    const char* quote = "'";
    for(char l : target){
        if((int) nmap[l] == 0 && l != *quote){encrypted.push_back(l);}

        else{encrypted.push_back(nmap[l]);}
            
    }
    return encrypted;

}

std::string dcrypt(std::string target){
    std::string decrypted;
    std::map <char, char> nmap;
    int pos = 0;

    for(char c : str){
        nmap[c] = alphabet.at(pos);
        pos++;
            
    }

    const char* quote = "'";
    for(char l : target){
            
        if((int)l == 0){decrypted.push_back(*quote);}

        else if((int) nmap[l] == 0){decrypted.push_back(l);}
            
        else{decrypted.push_back(nmap[l]);} 
    }

    return decrypted;
    
}

// sleeps for five seconds
void tempsleep(){
    std::chrono::seconds duration(5);
    std::this_thread::sleep_for(duration);
}

#endif

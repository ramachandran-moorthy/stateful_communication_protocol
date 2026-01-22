#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

using namespace std;

int main()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    cout << "Server listening on port 8080\n";

    sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int conn_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);
    if (conn_fd < 0) {
        perror("accept");
        close(server_fd);
        return 1;
    }

    cout << "Connection accepted\n";






    close(conn_fd);
    close(server_fd);
    return 0;
}
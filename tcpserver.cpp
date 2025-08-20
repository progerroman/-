#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <vector>
#include <string> 

#define MAX_MSG_PAYLOAD_SIZE (400000)
#define HEADER_SIZE (23)
#define RECV_BUFFER_SIZE (MAX_MSG_PAYLOAD_SIZE + HEADER_SIZE + 1024)

// Структура для хранения информации о клиенте
struct client {
    SOCKET cs;              // Сокет клиента
    struct sockaddr_in addr;// Адрес клиента (IP и порт)
    WSAEVENT event;         // Событие для данного клиента
    bool put_received;      // Флаг, получена ли команда "put"
    char recv_buffer[RECV_BUFFER_SIZE]; // Буфер для накопления данных
    int bytes_in_buffer;    // Количество байт в буфере
    std::string log_buffer; // Буфер для накопления логов (сообщений для записи в файл)

    client() : cs(INVALID_SOCKET), event(WSA_INVALID_EVENT), put_received(false), bytes_in_buffer(0) {
        memset(&addr, 0, sizeof(addr));
        memset(recv_buffer, 0, RECV_BUFFER_SIZE);
    }
};

std::vector<client> clients;
bool stop_server = false;
FILE* log_file = NULL;

// --- Вспомогательные функции ---

int set_non_block_mode(SOCKET s) {
    unsigned long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode);
}

bool init_winsock() {
    WSADATA wsa_data;
    return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
}

void deinit_winsock() {
    WSACleanup();
}

void sock_err(const char* function, SOCKET s, const char* message = "") {
    int err = WSAGetLastError();
    fprintf(stderr, "ERROR: %s: socket error %d. %s\n", function, err, message);
}

void s_close(SOCKET s) {
    if (s != INVALID_SOCKET) {
        closesocket(s);
    }
}

void event_close(WSAEVENT h) {
    if (h != WSA_INVALID_EVENT) {
        WSACloseEvent(h);
    }
}

// Запись буфера логов клиента в файл
void flush_client_log_to_file(client& cl) {
    if (log_file && !cl.log_buffer.empty()) {
        fprintf(log_file, "%s", cl.log_buffer.c_str());
        fflush(log_file);
        printf("INFO: Flushed log buffer for client %s:%u to msg.txt.\n",
               inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
        cl.log_buffer.clear(); // Очищаем буфер после записи
    }
}

bool remove_client(size_t index) {
    if (index >= clients.size()) {
        fprintf(stderr, "WARNING: remove_client called with invalid index %zu (clients size: %zu)\n", index, clients.size());
        return false;
    }

    printf("INFO: Client %s:%u disconnecting.\n",
           inet_ntoa(clients[index].addr.sin_addr),
           ntohs(clients[index].addr.sin_port));

    s_close(clients[index].cs);
    event_close(clients[index].event);
    clients[index].cs = INVALID_SOCKET;
    clients[index].event = WSA_INVALID_EVENT;

    clients.erase(clients.begin() + index);
    printf("INFO: Client removed. Total clients: %zu\n", clients.size());
    return true;
}

// --- Обработка данных клиента ---

void process_client_buffer(size_t client_index) {
    if (client_index >= clients.size()) {
        fprintf(stderr, "WARNING: process_client_buffer called with invalid index %zu (clients size: %zu)\n", client_index, clients.size());
        return;
    }
    client& cl = clients[client_index];

    while (true) {
        if (!cl.put_received) {
            if (cl.bytes_in_buffer >= 3) {
                if (memcmp(cl.recv_buffer, "put", 3) == 0) {
                    cl.put_received = true;
                    printf("INFO: 'put' received from client %s:%u\n",
                           inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
                    memmove(cl.recv_buffer, cl.recv_buffer + 3, cl.bytes_in_buffer - 3);
                    cl.bytes_in_buffer -= 3;
                } else {
                    fprintf(stderr, "ERROR: Invalid command from client %s:%u. Expected 'put'. Disconnecting.\n",
                            inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
                    remove_client(client_index);
                    return;
                }
            } else {
                break;
            }
        }

        if (cl.put_received) {
            const int min_message_len = HEADER_SIZE;
            if (cl.bytes_in_buffer < min_message_len) {
                break;
            }

            char* null_terminator = (char*)memchr(cl.recv_buffer + 22, '\0', cl.bytes_in_buffer - 22);
            if (null_terminator != NULL) {
                size_t total_msg_len = (null_terminator - cl.recv_buffer) + 1;

                uint8_t day = (uint8_t)cl.recv_buffer[4];
                uint8_t month = (uint8_t)cl.recv_buffer[5];
                uint16_t year_net;
                memcpy(&year_net, cl.recv_buffer + 6, 2);
                uint16_t year = ntohs(year_net);
                int16_t aa_net;
                memcpy(&aa_net, cl.recv_buffer + 8, 2);
                int16_t aa = ntohs(aa_net);
                char phone[13];
                memcpy(phone, cl.recv_buffer + 10, 12);
                phone[12] = '\0';
                char* msg_text = cl.recv_buffer + 22;

                printf("DEBUG: Parsed message [Day:%d, Mon:%d, Year:%d, AA:%d, Phone:%s, Text:'%.30s...'] from %s:%u\n",
                       day, month, year, aa, phone, msg_text, inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));

                int ss = send(cl.cs, "ok", 2, 0);
                bool ok_sent_successfully = false;

                if (ss == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK) {
                        fprintf(stderr, "WARNING: send 'ok' returned WSAEWOULDBLOCK for client %s:%u. Message NOT logged.\n",
                                inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
                    } else {
                        fprintf(stderr, "WARNING: send 'ok' failed (error %d) for client %s:%u. Client likely disconnected (nowait?). Message NOT logged.\n",
                                err, inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
                    }
                } else if (ss == 2) {
                    ok_sent_successfully = true;
                    printf("DEBUG: Sent 'ok' to client %s:%u\n", inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
                } else {
                    fprintf(stderr, "WARNING: send 'ok' returned %d bytes (expected 2) for client %s:%u. Message NOT logged.\n",
                            ss, inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
                }

                // Добавляем сообщение в буфер логов клиента, но не записываем в файл сразу
                if (ok_sent_successfully) {
                    char log_entry[RECV_BUFFER_SIZE];
                    sprintf(log_entry, "%s:%u %02d.%02d.%04d %d %s %s\n",
                            inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port),
                            day, month, year, aa, phone, msg_text);
                    cl.log_buffer += log_entry;

                    if (strcmp(msg_text, "stop") == 0) {
                        printf("INFO: Stop message received from %s:%u. Server will shut down after flush.\n",
                               inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
                        stop_server = true;
                    }
                }

                memmove(cl.recv_buffer, cl.recv_buffer + total_msg_len, cl.bytes_in_buffer - total_msg_len);
                cl.bytes_in_buffer -= total_msg_len;

                if (stop_server) return;
            } else {
                if (cl.bytes_in_buffer >= RECV_BUFFER_SIZE) {
                    fprintf(stderr, "ERROR: Client %s:%u buffer overflow (%d bytes). Disconnecting.\n",
                            inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port), cl.bytes_in_buffer);
                    remove_client(client_index);
                    return;
                }
                break;
            }
        }
    }
}

void handle_client_read(size_t client_index) {
    if (client_index >= clients.size()) {
        fprintf(stderr, "WARNING: handle_client_read called with invalid index %zu (clients size: %zu)\n", client_index, clients.size());
        return;
    }
    client& cl = clients[client_index];
    char temp_buffer[4096];

    int r = recv(cl.cs, temp_buffer, sizeof(temp_buffer), 0);

    if (r > 0) {
        // Успешное чтение новых данных — клиент жив, можно записать предыдущие сообщения
        flush_client_log_to_file(cl);

        printf("DEBUG: Received %d bytes from client %s:%u\n", r, inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
        if (cl.bytes_in_buffer + r > RECV_BUFFER_SIZE) {
            fprintf(stderr, "ERROR: Client %s:%u buffer overflow on read. Disconnecting.\n",
                    inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
            remove_client(client_index);
            return;
        }
        memcpy(cl.recv_buffer + cl.bytes_in_buffer, temp_buffer, r);
        cl.bytes_in_buffer += r;
        process_client_buffer(client_index);
    } else if (r == 0) {
        flush_client_log_to_file(cl);
        printf("INFO: Client %s:%u closed connection (recv returned 0).\n",
               inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
        remove_client(client_index);
    } else {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            printf("DEBUG: recv returned WSAEWOULDBLOCK for client %s:%u\n", inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
        } else {
            fprintf(stderr, "ERROR: recv failed with error %d for client %s:%u. Disconnecting.\n",
                   err, inet_ntoa(cl.addr.sin_addr), ntohs(cl.addr.sin_port));
            remove_client(client_index); // Аварийное отключение — буфер не записываем
        }
    }
}

// --- Основная функция main ---

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }
    unsigned short port = atoi(argv[1]);
    if (port == 0) {
        fprintf(stderr, "ERROR: Invalid port number provided: %s\n", argv[1]);
        return 1;
    }

    if (!init_winsock()) {
        fprintf(stderr, "ERROR: WSAStartup failed\n");
        return 1;
    }

    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        sock_err("socket", listen_socket);
        deinit_winsock();
        return 1;
    }

    if (set_non_block_mode(listen_socket) == SOCKET_ERROR) {
        sock_err("ioctlsocket (listen)", listen_socket);
        s_close(listen_socket);
        deinit_winsock();
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        sock_err("bind", listen_socket);
        s_close(listen_socket);
        deinit_winsock();
        return 1;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        sock_err("listen", listen_socket);
        s_close(listen_socket);
        deinit_winsock();
        return 1;
    }
    printf("INFO: Server listening on port %u\n", port);

    log_file = fopen("msg.txt", "a");
    if (log_file == NULL) {
        perror("ERROR: Failed to open msg.txt for appending");
        s_close(listen_socket);
        deinit_winsock();
        return 1;
    }

    WSAEVENT listen_event = WSACreateEvent();
    if (listen_event == WSA_INVALID_EVENT) {
        sock_err("WSACreateEvent (listen)", listen_socket);
        fclose(log_file);
        s_close(listen_socket);
        deinit_winsock();
        return 1;
    }
    if (WSAEventSelect(listen_socket, listen_event, FD_ACCEPT) == SOCKET_ERROR) {
        sock_err("WSAEventSelect (listen)", listen_socket);
        event_close(listen_event);
        fclose(log_file);
        s_close(listen_socket);
        deinit_winsock();
        return 1;
    }

    printf("INFO: Starting main event loop...\n");
    while (!stop_server) {
        std::vector<WSAEVENT> events;
        events.push_back(listen_event);

        for (size_t i = 0; i < clients.size(); ++i) {
            if (events.size() >= (size_t)WSA_MAXIMUM_WAIT_EVENTS) {
                fprintf(stderr, "WARNING: Reached WSA_MAXIMUM_WAIT_EVENTS limit (%d). Some client events might be delayed.\n", WSA_MAXIMUM_WAIT_EVENTS);
                break;
            }
            if (clients[i].event != WSA_INVALID_EVENT) {
                events.push_back(clients[i].event);
            }
        }

        DWORD wait_result = WSAWaitForMultipleEvents(
            (DWORD)events.size(), events.data(), FALSE, 100, FALSE);

        if (wait_result == WSA_WAIT_FAILED) {
            sock_err("WSAWaitForMultipleEvents", INVALID_SOCKET);
            break;
        }
        if (wait_result == WSA_WAIT_TIMEOUT) {
            continue;
        }

        int signaled_event_index = wait_result - WSA_WAIT_EVENT_0;
        if (signaled_event_index < 0 || signaled_event_index >= (int)events.size()) {
            fprintf(stderr, "ERROR: WSAWaitForMultipleEvents returned invalid index: %d (events size: %zu)\n", signaled_event_index, events.size());
            continue;
        }

        WSAEVENT signaled_event = events[signaled_event_index];

        if (signaled_event == listen_event) {
            WSANETWORKEVENTS network_events;
            if (WSAEnumNetworkEvents(listen_socket, listen_event, &network_events) == SOCKET_ERROR) {
                sock_err("WSAEnumNetworkEvents (listen)", listen_socket);
                continue;
            }
            if (network_events.lNetworkEvents & FD_ACCEPT) {
                if (network_events.iErrorCode[FD_ACCEPT_BIT] != 0) {
                    fprintf(stderr, "ERROR: FD_ACCEPT failed with error %d\n", network_events.iErrorCode[FD_ACCEPT_BIT]);
                } else {
                    while (true) {
                        struct sockaddr_in client_addr;
                        int addrlen = sizeof(client_addr);
                        SOCKET new_client_socket = accept(listen_socket, (struct sockaddr*)&client_addr, &addrlen);

                        if (new_client_socket == INVALID_SOCKET) {
                            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                                break;
                            } else {
                                sock_err("accept", listen_socket);
                                break;
                            }
                        }

                        printf("INFO: Client connected: %s:%u\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                        const size_t MAX_CLIENTS = 1000;
                        if (clients.size() >= MAX_CLIENTS) {
                            fprintf(stderr, "WARNING: Maximum client limit (%zu) reached. Connection rejected.\n", MAX_CLIENTS);
                            s_close(new_client_socket);
                            continue;
                        }
                        if (set_non_block_mode(new_client_socket) == SOCKET_ERROR) {
                            sock_err("ioctlsocket (client)", new_client_socket);
                            s_close(new_client_socket);
                            continue;
                        }
                        WSAEVENT client_event = WSACreateEvent();
                        if (client_event == WSA_INVALID_EVENT) {
                            sock_err("WSACreateEvent (client)", new_client_socket);
                            s_close(new_client_socket);
                            continue;
                        }
                        if (WSAEventSelect(new_client_socket, client_event, FD_READ | FD_CLOSE) == SOCKET_ERROR) {
                            sock_err("WSAEventSelect (client)", new_client_socket);
                            event_close(client_event);
                            s_close(new_client_socket);
                            continue;
                        }

                        client new_cl;
                        new_cl.cs = new_client_socket;
                        new_cl.addr = client_addr;
                        new_cl.event = client_event;
                        clients.push_back(new_cl);
                        printf("INFO: Client added. Total clients: %zu\n", clients.size());
                    }
                }
            }
        } else {
            size_t client_idx = (size_t)-1;
            bool found_client = false;

            size_t potential_idx = (size_t)signaled_event_index - 1;
            if (potential_idx < clients.size() && clients[potential_idx].event == signaled_event) {
                client_idx = potential_idx;
                found_client = true;
            } else {
                for (size_t i = 0; i < clients.size(); ++i) {
                    if (clients[i].event == signaled_event) {
                        client_idx = i;
                        found_client = true;
                        break;
                    }
                }
            }

            if (!found_client) {
                fprintf(stderr, "ERROR: Could not find client for signaled event %p (index %d). Ignoring.\n", signaled_event, signaled_event_index);
                if (signaled_event != listen_event) {
                    event_close(signaled_event);
                }
                continue;
            }

            WSANETWORKEVENTS network_events;
            if (WSAEnumNetworkEvents(clients[client_idx].cs, signaled_event, &network_events) == SOCKET_ERROR) {
                sock_err("WSAEnumNetworkEvents (client)", clients[client_idx].cs);
                remove_client(client_idx);
                continue;
            }

            if (network_events.lNetworkEvents & FD_READ) {
                if (network_events.iErrorCode[FD_READ_BIT] != 0) {
                    fprintf(stderr, "ERROR: FD_READ failed with error %d for client %s:%u. Disconnecting.\n",
                            network_events.iErrorCode[FD_READ_BIT], inet_ntoa(clients[client_idx].addr.sin_addr), ntohs(clients[client_idx].addr.sin_port));
                    remove_client(client_idx);
                    continue;
                } else {
                    handle_client_read(client_idx);
                }
            }

            if (stop_server) break;

            bool client_still_exists_after_read = false;
            if (client_idx < clients.size() && clients[client_idx].event == signaled_event) {
                client_still_exists_after_read = true;
            }

            if (client_still_exists_after_read && (network_events.lNetworkEvents & FD_CLOSE)) {
                if (network_events.iErrorCode[FD_CLOSE_BIT] != 0) {
                    fprintf(stderr, "WARNING: FD_CLOSE received with error %d for client %s:%u. Force closing.\n",
                            network_events.iErrorCode[FD_CLOSE_BIT], inet_ntoa(clients[client_idx].addr.sin_addr), ntohs(clients[client_idx].addr.sin_port));
                    remove_client(client_idx); // Аварийное закрытие — буфер не записываем
                } else {
                    flush_client_log_to_file(clients[client_idx]); 
                    printf("INFO: FD_CLOSE event received normally for client %s:%u.\n",
                           inet_ntoa(clients[client_idx].addr.sin_addr), ntohs(clients[client_idx].addr.sin_port));
                    remove_client(client_idx);
                }
            }
        }
    }

    printf("INFO: Shutting down server...\n");
    printf("INFO: Closing %zu remaining client connections...\n", clients.size());
    for (int i = (int)clients.size() - 1; i >= 0; --i) {
        flush_client_log_to_file(clients[i]); // Записываем буферы перед завершением
        remove_client((size_t)i);
    }
    clients.clear();

    s_close(listen_socket);
    event_close(listen_event);

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
        printf("INFO: Log file closed.\n");
    }

    deinit_winsock();
    printf("INFO: Server stopped gracefully.\n");
    return 0;
}

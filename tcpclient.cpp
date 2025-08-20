#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Структура пакета данных, отправляемого серверу
struct network_packet {
    unsigned int sequence_id;    // Номер пакета (4 байта в сетевом порядке)
    unsigned char day;          // День (1 байт)
    unsigned char month;        // Месяц (1 байт)
    unsigned short year;        // Год (2 байта в сетевом порядке)
    short priority;             // Приоритет (2 байта в сетевом порядке)
    char phone[12];             // Номер телефона (12 байт, строка)
    unsigned int content_length; // Длина содержимого (вычисляется)
    char* content;              // Указатель на содержимое (динамическая строка)
};

// Объявления функций (прототипы)
int initialize_network();                        // Инициализация сетевой подсистемы (заглушка)
void cleanup_network();                          // Очистка сетевой подсистемы (заглушка)
int handle_socket_error(const char* operation, int socket_fd); // Обработка ошибок сокетов
int create_socket();                             // Создание сокета с тайм-аутом
void close_socket(int socket_fd);                // Закрытие сокета
int parse_address(const char* input, char** ip_address, char** port_number); // Парсинг адреса ip:port
struct network_packet parse_packet_data(const char* input, unsigned int sequence); // Парсинг строки в пакет
int send_packet(int socket_fd, struct network_packet packet); // Отправка пакета серверу
int receive_acknowledgment(int socket_fd);       // Получение подтверждения от сервера
int set_operation_mode(int socket_fd);           // Установка режима работы (отправка "put")



int initialize_network() { 
    return 1; 
}


void cleanup_network() {}


int handle_socket_error(const char* operation, int socket_fd) {
    int error_code = errno;
    printf("%s: socket error: %d\n", operation, error_code);
    return -1;
}

// Создание TCP-сокета с тайм-аутом
int create_socket() {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0); 
    if (socket_fd < 0) return handle_socket_error("socket", socket_fd); // Ошибка создания
    struct timeval timeout; // Структура для установки тайм-аута
    timeout.tv_sec = 5;    // 5 секунд
    timeout.tv_usec = 0;   // 0 микросекунд
    // Тайм-аут для отправки данных
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    // Тайм-аут для получения данных
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    return socket_fd; // Возвращаем дескриптор сокета
}

// Socket cleanup
void close_socket(int socket_fd) { 
    close(socket_fd); 
}

#define MAX_IP_LENGTH 15
#define MAX_PORT_LENGTH 16

// Поиск позиции двоеточия в строке адреса
static int find_colon_position(const char* input, int max_length) {
    int position = 0;
    while (position < max_length && input[position] != '\0') { 
        if (input[position] == ':') return position; 
        position++;
    }
    return -1; 
}

// Проверка формата адреса
static int validate_address_format(int colon_pos, int total_length) {
    if (colon_pos <= 0) { // Нет двоеточия или оно в начале
        printf("Error: No colon found in address string\n");
        return 0;
    }
    if (colon_pos > MAX_IP_LENGTH) { // IP-адрес слишком длинный
        printf("Error: IP portion exceeds %d characters\n", MAX_IP_LENGTH);
        return 0;
    }
    if (total_length - colon_pos - 1 > MAX_PORT_LENGTH) { // Порт слишком длинный
        printf("Error: Port portion exceeds %d characters\n", MAX_PORT_LENGTH);
        return 0;
    }
    return 1; // Формат корректен
}


static void extract_substring(const char* source, char* destination, int start, int length) {
    for (int i = 0; i < length; i++) {
        destination[i] = source[start + i]; // Копируем символы
    }
    destination[length] = '\0'; // Добавляем нулевой терминатор
}


int parse_address(const char* input, char** ip_address, char** port_number) {
    *ip_address = NULL; // Инициализируем указатели как NULL
    *port_number = NULL;
    int input_length = strlen(input); // Длина входной строки
    int colon_position = find_colon_position(input, input_length + 1); // Ищем двоеточие
    if (!validate_address_format(colon_position, input_length)) return -1; // Проверяем формат
    int ip_length = colon_position; // Длина IP-адреса
    int port_length = input_length - colon_position - 1; // Длина порта
    char* ip_buffer = (char*)malloc(sizeof(char) * (ip_length + 1)); // Выделяем память под IP
    char* port_buffer = (char*)malloc(sizeof(char) * (port_length + 1)); // Выделяем память под порт
    if (!ip_buffer || !port_buffer) { // Проверка успешности выделения памяти
        printf("Memory allocation failed\n");
        free(ip_buffer); // Освобождаем память, если что-то выделено
        free(port_buffer);
        return -1;
    }
    extract_substring(input, ip_buffer, 0, ip_length); // Извлекаем IP
    extract_substring(input, port_buffer, colon_position + 1, port_length); // Извлекаем порт
    *ip_address = ip_buffer; // Устанавливаем указатели на выделенные буферы
    *port_number = port_buffer;
    return 0; // Успешно
}


// Парсинг числового поля из строки
static int parse_numeric_field(const char* source, int start, int length, char* buffer) {
    for (int i = 0; i < length; i++) {
        buffer[i] = source[start + i]; // Копируем символы
    }
    buffer[length] = '\0'; // Добавляем нулевой терминатор
    return atoi(buffer); // Преобразуем в число
}

static int find_next_space(const char* text, int start_pos) {
    int position = start_pos;
    while (text[position] != ' ' && text[position] != '\0') position++; // Ищем пробел или конец строки
    return position;
}

static void copy_fixed_field(const char* source, char* destination, int start, int field_length) {
    for (int i = 0; i < field_length; i++) {
        destination[i] = source[start + i]; // Копируем символы
    }
}

// Выделение памяти под содержимое пакета
static char* allocate_content(const char* input, int start_pos, unsigned int* length_out) {
    int total_length = strlen(input); // Общая длина строки
    *length_out = (total_length > start_pos) ? total_length - start_pos : 0; // Вычисляем длину содержимого
    char* content = (char*)malloc(*length_out + 1); // Выделяем память (+1 для нулевого терминатора)
    if (!content) { // Проверка выделения памяти
        *length_out = 0;
        return NULL;
    }
    if (*length_out > 0) { // Если есть содержимое
        for (unsigned int i = 0; i < *length_out; i++) {
            content[i] = input[start_pos + i]; // Копируем содержимое
        }
    }
    content[*length_out] = '\0'; // Добавляем нулевой терминатор
    return content;
}


struct network_packet parse_packet_data(const char* input, unsigned int sequence) {
    struct network_packet packet = {0}; 
    packet.sequence_id = sequence; // Устанавливаем номер пакета
    if (!input || input[0] == '\0') { 
        packet.content_length = 0;
        packet.content = NULL;
        return packet;
    }
    char temp_day[3], temp_month[3], temp_year[5], temp_priority[8]; 
    packet.day = (unsigned char)parse_numeric_field(input, 0, 2, temp_day); // Парсим день
    packet.month = (unsigned char)parse_numeric_field(input, 3, 2, temp_month); // Парсим месяц
    packet.year = (unsigned short)parse_numeric_field(input, 6, 4, temp_year); // Парсим год
    const int date_end = 10; 
    int priority_end = find_next_space(input, date_end + 1); 
    int phone_end = priority_end + 13; 
    int priority_length = priority_end - date_end - 1; 
    if (priority_length > 0 && priority_length < 8) { 
        for (int i = 0; i < priority_length; i++) {
            temp_priority[i] = input[date_end + 1 + i]; 
        }
        temp_priority[priority_length] = '\0'; 
        packet.priority = (short)atoi(temp_priority); 
    }
    copy_fixed_field(input, packet.phone, priority_end + 1, 12); 
    packet.content = allocate_content(input, phone_end + 1, &packet.content_length); 
    if (!packet.content && packet.content_length > 0) { 
        packet.content = (char*)malloc(1); 
        packet.content[0] = '\0';
        packet.content_length = 0;
    }
    return packet; 
}

// Отправка данных через сокет
static int send_data(int socket_fd, const void* buffer, size_t length, const char* description) {
    int result = send(socket_fd, buffer, length, MSG_NOSIGNAL); 
    if (result < 0) { // Ошибка отправки
        if (errno == EPIPE || errno == ECONNRESET) { // Соединение разорвано сервером
            printf("Connection closed by server during %s (error %d)\n", description, errno);
            return -1;
        }
        handle_socket_error(description, socket_fd); // Общая обработка ошибки
        return -1;
    }
    return 0; // Успешно
}


int send_packet(int socket_fd, struct network_packet packet) {
    // Структура для описания полей пакета
    struct field_info {
        const void* data_ptr;    // Указатель на данные
        size_t size;             // Размер данных
        const char* description; // Описание для вывода ошибок
    };
    uint32_t sequence_net = htonl(packet.sequence_id);
    uint16_t year_net = htons(packet.year);
    int16_t priority_net = htons(packet.priority);
    char terminator = '\0'; // Нулевой терминатор для содержимого
    struct field_info fields[] = {
        {&sequence_net, sizeof(sequence_net), "send sequence"},
        {&packet.day, sizeof(packet.day), "send day"},
        {&packet.month, sizeof(packet.month), "send month"},
        {&year_net, sizeof(year_net), "send year"},
        {&priority_net, sizeof(priority_net), "send priority"},
        {packet.phone, 12, "send phone"},
        {packet.content, packet.content_length, "send content"},
        {&terminator, 1, "send terminator"}
    };
    const int field_count = sizeof(fields) / sizeof(fields[0]); 
    for (int i = 0; i < field_count; i++) { 
        if (send_data(socket_fd, fields[i].data_ptr, fields[i].size, fields[i].description) < 0) {
            return -1; 
        }
    }
    return 0; 
}


int receive_acknowledgment(int socket_fd) {
    char response[2] = {0}; // Буфер для "ok" (2 байта)
    int bytes_received;
    do {
        bytes_received = recv(socket_fd, response, 2, 0); 
        if (bytes_received == 2) return 0; 
        if (bytes_received == 1) { 
            int second_byte;
            do {
                second_byte = recv(socket_fd, response + 1, 1, 0); 
                if (second_byte == 1) return 0; 
                if (second_byte == 0) {
                    printf("Connection closed by server during partial read\n");
                    return -1;
                }
                if (second_byte < 0) { 
                    handle_socket_error("recv partial", socket_fd);
                    return -1;
                }
            } while (second_byte == 0);
        }
        if (bytes_received == 0) { 
            printf("Connection closed by server\n");
            return -1;
        }
        if (bytes_received < 0) { 
            handle_socket_error("recv", socket_fd);
            return -1;
        }
    } while (bytes_received == 0);
    return 0; 
}

// Отправляет серверу команду "put" 
int set_operation_mode(int socket_fd) {
    const char mode_command[] = {'p', 'u', 't'};
    int send_result = send(socket_fd, mode_command, 3, 0);
    if (send_result < 0) {
        return handle_socket_error("Operation mode signal", socket_fd);
    }
    return 0;
}

#define MAX_CONNECTION_ATTEMPTS 10      
#define CONNECTION_DELAY_US (100 * 1000) 

static int check_arguments(int argc, char** argv) {
    if (argc != 3) { 
        fprintf(stderr, "Expected usage: %s <address:port> <input_file>\n", argv[0]);
        return -1;
    }
    return 0; 
}


static int connect_to_server(int socket_fd, const char* ip_address, const char* port_number) {
    struct sockaddr_in server = {0}; 
    server.sin_family = AF_INET; 
    server.sin_port = htons(atoi(port_number)); 
    server.sin_addr.s_addr = inet_addr(ip_address); 

    int attempt = 0; 
    int connection_result;

    while (attempt < MAX_CONNECTION_ATTEMPTS) { // Пробуем подключиться
        attempt++;
        printf("Attempting connection #%d ... ", attempt);
        connection_result = connect(socket_fd, (struct sockaddr*)&server, sizeof(server)); 
        
        if (!connection_result) { 
            printf("Connection established\n");
            return set_operation_mode(socket_fd); // Отправляем "put"
        }
        
        printf("Unsuccessful\n");
        usleep(CONNECTION_DELAY_US); 
    }
    
    printf("All %d connection attempts failed\n", MAX_CONNECTION_ATTEMPTS);
    return handle_socket_error("Network link", socket_fd); 
}


static int process_file_and_send(int socket_fd, FILE* input_file, int* packets_sent) {
    char* line_buffer = NULL; 
    size_t buffer_capacity = 0; 
    ssize_t line_length;
    unsigned int packet_sequence = 0; 
    *packets_sent = 0; 

    // Читаем строки из файла
    while ((line_length = getline(&line_buffer, &buffer_capacity, input_file)) != -1) {
        if (line_length > 0 && line_buffer[line_length - 1] == '\n') { // Убираем символ новой строки
            line_buffer[line_length - 1] = '\0';
        }
        if (!line_buffer[0]) {
            continue;
        }
        struct network_packet packet = parse_packet_data(line_buffer, packet_sequence); 
        int send_result = send_packet(socket_fd, packet); 
        if (packet.content) { 
            free(packet.content);
        }
        if (send_result != 0) { 
            return -1;
        }
        packet_sequence++; 
        (*packets_sent)++; 
    }
    if (line_buffer) { 
        free(line_buffer);
    }
    return 0; 
}


static int receive_all_acks(int socket_fd, int packet_count) {
    for (int i = 0; i < packet_count; i++) { 
        if (receive_acknowledgment(socket_fd) != 0) { 
            printf("Failed to receive acknowledgment for packet %d\n", i);
            return -1;
        }
    }
    return 0; 
}



int main(int argc, char* argv[]) {
    initialize_network(); 
    if (check_arguments(argc, argv) < 0) { 
        return -1;
    }

    char* server_ip = NULL; 
    char* server_port = NULL; 
    if (parse_address(argv[1], &server_ip, &server_port) < 0) { 
        return 1;
    }

    int socket_fd = create_socket(); // Создаем сокет
    if (socket_fd < 0) { // Ошибка создания
        free(server_ip);
        free(server_port);
        return -1;
    }

    int connection_result = connect_to_server(socket_fd, server_ip, server_port); 
    if (connection_result < 0) { 
        close_socket(socket_fd);
        free(server_ip);
        free(server_port);
        return -1;
    }

    FILE* input_file = fopen(argv[2], "r"); 
    if (!input_file) { 
        fprintf(stderr, "Unable to access file: %s\n", argv[2]);
        close_socket(socket_fd);
        free(server_ip);
        free(server_port);
        return -1;
    }

    int packets_sent; 
    if (process_file_and_send(socket_fd, input_file, &packets_sent) < 0) { 
        fclose(input_file);
        close_socket(socket_fd);
        free(server_ip);
        free(server_port);
        return -1;
    }

    fclose(input_file); 

    if (receive_all_acks(socket_fd, packets_sent) < 0) { // Получаем подтверждения
        close_socket(socket_fd);
        free(server_ip);
        free(server_port);
        return -1;
    }

    close_socket(socket_fd); 
    cleanup_network(); 
    free(server_ip); // Освобождаем память
    free(server_port);

    return 0;
}

import socket

def start_client(server_host, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))

    while True:
        command = input("Enter command: ")
        client_socket.send(command.encode())
        output = client_socket.recv(1024).decode()
        print(output)
        if command.lower() == "exit":
            break

    client_socket.close()

if __name__ == "__main__":
    SERVER_HOST = '127.0.0.1'  # Server IP address
    SERVER_PORT = 12345        # Server port number
    start_client(SERVER_HOST, SERVER_PORT)

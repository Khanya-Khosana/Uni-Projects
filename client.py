import socket

def client():
    server_host= input("Please enter your IP Address: ").strip()
    stud_no = input("Please enter your student number: ").strip()

    PORT = 12345

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_host, PORT))

        client_socket.sendall(stud_no.encode())

        while True:
            server_message = client_socket.recv(1024).decode()

            if not server_message:
                print("Server has closed the connection")
                break

            print(f"Server: {server_message}")

            if"Bottle is full" in server_message:
                print("The bottle is Full")
                break

    except ConnectionRefusedError:
        print("Could not connect to the server")
    finally:
        client_socket.close()
        print("Disconnected from Server")

if __name__=="__main__":
 client()


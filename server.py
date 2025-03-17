import socket
import threading
import random

# Server Configuration
HOST = "172.21.5.204"#listen on all available network interfaces
PORT = 12345
MAX_CAPACITY = 2000 # 2-litre bottle (2000 mL)


clients = []
student_info = {} # Stores client IP and student number
turn_index = 0
current_fill = 0
lock = threading.Lock()

def handle_client(client_socket, client_address):
    global turn_index, current_fill
    try:
        # Receive student number from client
        student_number = client_socket.recv(1024).decode().strip()
        student_info[client_socket] = (client_address[0], student_number)
        print(f"New connection from {client_address[0]} | Student Number: {student_number}")
        while True:
            with lock:
                if current_fill >= MAX_CAPACITY:
                    client_socket.sendall("Bottle is full! Stopping process.\n".encode())
                    break
                if len(clients) >0 and clients[turn_index] == client_socket:
                    pour_amount = random.randint(0, 50)
                    current_fill += pour_amount
                    message = (f"Your turn! You poured {pour_amount} mL. "
                    f"Current bottle level: {current_fill}/{MAX_CAPACITY} mL\n")
                    client_socket.sendall(message.encode())

                    turn_index = (turn_index + 1) % len(clients) # Move to the next client
                else:
                    client_socket.sendall("Not your turn. Please wait.\n".encode())
    except ConnectionResetError:
        print(f"Client {client_address[0]} disconnected.")
    finally:
        client_socket.close()
def start_server():
 global clients
 server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
 server_socket.bind((HOST, PORT))
 server_socket.listen(5)
 print(f"Server listening on {HOST}:{PORT}")
 while True:
    client_socket, client_address = server_socket.accept()
    with lock:
        clients.append(client_socket)
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()
if __name__ == "__main__":
 start_server()

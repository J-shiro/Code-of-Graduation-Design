from utils import receive_replicate_response as rrr
import threading
import socket
import asyncio

# 对接收到的不同数据包做不同处理, 其中接受挑战后需要做进一步的返回响应
def client_handler(client_socket, cloud):
    index_bytes = client_socket.recv(4)
    index = int.from_bytes(index_bytes)
    
    if index == 2:
        D_file, sigma_list, ini_ga, ini_hb, alpha_prime, beta_prime, sk, u = cloud.Receive_Tag_and_File(client_socket)
        r_D_file = cloud.Replicate_r_file(D_file)
        cloud.Store_file_and_replica()
        
    elif index == 3:
        tuples, R, S = cloud.Receive_Challenge(client_socket)
        mu, sigma = cloud.server_Response()
        cloud.Send_Response(mu, sigma, client_socket)
    elif index == 6:
        rs, ns, v_s = cloud.Receive_s_verify(client_socket)
        cloud.Send_back_sectors(rs, ns, v_s, client_socket)
        
        pass

def main():
    # 创建实例
    cloud = rrr.RRR()

    # 套接字绑定IP和端口
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 15323)
    server_socket.bind(server_address)

    # 监听连接
    server_socket.listen(1)

    print("等待用户连接... ")
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print("用户连接: ", client_address)

            client_thread = threading.Thread(target=client_handler, args=(client_socket,cloud))
            client_thread.start()
    finally:
        server_socket.close()
    
if __name__ == "__main__":
    main()
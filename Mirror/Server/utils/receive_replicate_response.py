import struct
import numpy as np
import os
import socket
import gmpy2
import sys
from utils import lfsr
import concurrent.futures
import time

sys.set_int_max_str_digits(10000000)
# 设置打印选项，禁用阵列截断和省略号
np.set_printoptions(threshold=np.inf)

'''
    实现: 
    0. 保持接收数据 finish
    1. 接收文件及标签 finish
    2. 创建副本 finish
    3. 存储文件及副本在本地
    4. 接收挑战 finish
    5. 返回响应
'''

class RRR:
    def __init__(self) -> None:
        self.file = None        # 获取到的处理后的文件D, 为测试时的暂存
        self.sigma_list = []
        
        # 初始的ga和hb值
        self.ini_ga = None
        self.ini_hb = None

        # 最终生成的ga和hb的矩阵
        self.ga = None
        self.hb = None
        self.alpha_prime = []
        self.beta_prime = []

        self.r_D_file = None    # 为测试时的暂存
        self.tuples = []
        self.R = []
        
        self.r = 0
        self.nambda = 0
        self.n = 0
        self.s = 0

    # 通过ini_ga和ini_hb来生成最终的ga和hb
    def Generate_ga_hb(self, ini_ga, ini_hb, alpha_prime, beta_prime):
        
        # 传入的 ini_ga 和 ini_hb 为初始: r * (2*nambda) 的numpy矩阵

        lfsr_instance = lfsr.LFSR()

        # 最终的ga和hb
        ga_final = []
        hb_final = []

        # # 使用ThreadPoolExecutor来并行计算ga_final和hb_final
        # with concurrent.futures.ThreadPoolExecutor() as executor:
        #     # 计算ga_final
        #     ga_futures = [executor.submit(lfsr_instance.public_lfsr_with_no_g, ini_ga[i], self.n * self.s, alpha_prime) for i in range(self.r)]
        #     ga_final = [future.result() for future in concurrent.futures.as_completed(ga_futures)]
            
        #     # 计算hb_final
        #     hb_futures = [executor.submit(lfsr_instance.public_lfsr_with_no_g, ini_hb[i], self.n * self.s, beta_prime) for i in range(self.r)]
        #     hb_final = [future.result() for future in concurrent.futures.as_completed(hb_futures)]

        for i in range(self.r):
            ga_final_tmp = lfsr_instance.public_lfsr_with_no_g(ini_ga[i], self.n * self.s, alpha_prime, self.N)
            ga_final.append(ga_final_tmp)

        for i in range(self.r):
            hb_final_tmp = lfsr_instance.public_lfsr_with_no_g(ini_hb[i], self.n * self.s, beta_prime, self.N)
            hb_final.append(hb_final_tmp)
        
        ga_final = np.array(ga_final).reshape(self.r, self.n * self.s)
        hb_final = np.array(hb_final).reshape(self.r, self.n * self.s)

        # print(ga_final)

        self.ga = ga_final
        self.hb = hb_final

        return ga_final, hb_final

    # 接收标签及文件
    def Receive_Tag_and_File(self, connection):
        # 获取N
        N_len_bytes = connection.recv(4)
        N_len = struct.unpack('!I', N_len_bytes)[0]

        N_bytes = b''
        while len(N_bytes) < N_len:
            N_bytes += connection.recv(N_len - len(N_bytes))

        N = int(N_bytes)
        self.N = N

        # 获取文件shape
        data_shape_length = connection.recv(8)
        
        f_row, f_col = struct.unpack("!II", data_shape_length)

        # f_row为n, f_col为s
        self.n = f_row
        self.s = f_col

        # 接收文件D
        D_length_bytes = connection.recv(4)

        D_length = struct.unpack('!I', D_length_bytes)[0]

        D_list = []

        D_length_over = 0
        while D_length_over < D_length:
            # 接收 ga 矩阵中每一个元素
            D_each_length_bytes = connection.recv(4)
            if not D_each_length_bytes:
                break

            D_each_length = struct.unpack('!I', D_each_length_bytes)[0]

            D_bytes = b''
            while len(D_bytes) < D_each_length:
                D_bytes += connection.recv(D_each_length - len(D_bytes))
            
            D_list.append(D_bytes)
            D_length_over += D_each_length

        D_list = [int(x) for x in D_list]
        D_file = np.array(D_list).reshape(f_row, f_col)

        self.file = D_file

        sigma_list = []

        sigma_strlen_bytes = connection.recv(4)
        sigma_strlen = struct.unpack('!I', sigma_strlen_bytes)[0]
        
        sigma_strlen_over = 0
        while sigma_strlen_over < sigma_strlen:
            # 接收 sigma
            sigma_length_bytes = connection.recv(4)
            if not sigma_length_bytes:
                break

            sigma_length = struct.unpack('!I', sigma_length_bytes)[0]

            sigma_bytes = b''
            while len(sigma_bytes) < sigma_length:
                sigma_bytes += connection.recv(sigma_length - len(sigma_bytes))
            
            sigma_list.append(sigma_bytes)
            sigma_strlen_over += sigma_length

        sigma_list = [int(x) for x in sigma_list]

        self.sigma_list = sigma_list

        # 接受shape的行与列, 一个整数4字节
        received_data = connection.recv(8)

        # 解包成两个无符号整数, row为r, col为2*nambda
        row, col = struct.unpack("!II", received_data)
        self.r = row
        self.nambda = col // 2

        # 接收 ga, hb
        ga_length_bytes = connection.recv(4)

        ga_length = struct.unpack('!I', ga_length_bytes)[0]

        ga_list = []

        ga_length_over = 0
        while ga_length_over < ga_length:
            # 接收 ga 矩阵中每一个元素
            ga_each_length_bytes = connection.recv(4)
            if not ga_each_length_bytes:
                break

            ga_each_length = struct.unpack('!I', ga_each_length_bytes)[0]

            ga_bytes = b''
            while len(ga_bytes) < ga_each_length:
                ga_bytes += connection.recv(ga_each_length - len(ga_bytes))
            
            ga_list.append(ga_bytes)
            ga_length_over += ga_each_length

        ga_list = [int(x) for x in ga_list]
        ga = np.array(ga_list).reshape(row, col)

        self.ini_ga = ga

        hb_length_bytes = connection.recv(4)

        hb_length = struct.unpack('!I', hb_length_bytes)[0]

        hb_list = []

        hb_length_over = 0
        while hb_length_over < hb_length:
            # 接收 hb 矩阵中每一个元素
            hb_each_length_bytes = connection.recv(4)
            if not hb_each_length_bytes:
                break

            hb_each_length = struct.unpack('!I', hb_each_length_bytes)[0]

            hb_bytes = b''
            while len(hb_bytes) < hb_each_length:
                hb_bytes += connection.recv(hb_each_length - len(hb_bytes))
            
            hb_list.append(hb_bytes)
            hb_length_over += hb_each_length

        hb_list = [int(x) for x in hb_list]
        hb = np.array(hb_list).reshape(row, col)

        self.ini_hb = hb

        # 接收 alpha_prime, beta_prime
        received_data = b''
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            received_data += chunk # 接收完剩余所有数据

        ab_prime = struct.unpack("!"+ "I" * (len(received_data) // 4), received_data)

        prime_length = len(ab_prime) // 2
        alpha_prime = list(ab_prime[:prime_length])
        beta_prime = list(ab_prime[prime_length:])

        self.alpha_prime = alpha_prime
        self.beta_prime = beta_prime

        # 传入的ga和hb为初始: r * (2*nambda) 的numpy矩阵
        ga_final, hb_final = self.Generate_ga_hb(ga, hb, alpha_prime, beta_prime)


        return D_file, sigma_list, ga_final, hb_final, alpha_prime, beta_prime
    


    # 构建r个副本
    def Replicate_r_file(self, recv_D):

        replica_time_start = time.time()
        # 获取n, s, r
        n = recv_D.shape[0]
        s = recv_D.shape[1]
        r = self.ga.shape[0]

        replica_list = []
        # 将2维ga, hb,转换为3维: r*n*s
        ga_3d_matrix = self.ga.reshape(r, n, s)

        # 倒置hb
        hb_list = []

        for sub_hb in self.hb:
            # 对每个子数组进行倒置操作
            inverted_array = np.flip(sub_hb)
            hb_list.append(inverted_array)

        # 将列表转换为 ndarray
        hb_result_list = np.array(hb_list)
        hb_3d_matrix = hb_result_list.reshape(r, n, s)

        for sub_ga in ga_3d_matrix:
            temp = np.multiply(sub_ga, recv_D)
            replica_list.append(temp)

        replica_list = np.array(replica_list) # r*n*s

        # r*n*s: r个n*s的扇区d
        r_replicate_file = replica_list * hb_3d_matrix
        self.r_D_file = r_replicate_file

        replica_time_end = time.time()
        print("[Replicate]: 副本生成完毕, 耗时: ", replica_time_end-replica_time_start)

        return r_replicate_file

    # 存储文件及副本
    def Store_file_and_replica(self):

        # 文件及文件夹路径
        folder = 'file_folder'
        file_name = 'D_file.txt' 
        replica_name = 'r_file.txt'

        file_path = os.path.join(folder, file_name)
        with open(file_path, 'w') as file:
            file.write(np.array2string(self.file)) # 转换为字符串存储
        

        replica_path = os.path.join(folder, replica_name)
        with open(replica_path, 'w') as file:
            file.write(np.array2string(self.r_D_file))
        print("[Mirror]: 文件及副本存储成功")
        
    # 接收挑战
    def Receive_Challenge(self, connection):
            
        # 接收数据长度
        data_length = connection.recv(4)
        tuples_length = struct.unpack("!I", data_length)[0]

        # 解包元组
        tuples = []
        for _ in range(tuples_length):
            index_data = connection.recv(4)
            index = struct.unpack("!I", index_data)[0]
            value_length_data = connection.recv(4)
            value_length = struct.unpack("!I", value_length_data)[0]
            value_bytes = connection.recv(value_length)
            value = int(value_bytes.decode())
            tuples.append((index, value))

        self.tuples = tuples

        # 解包R的子集
        R_size_data = connection.recv(4)
        R_size = struct.unpack('!I', R_size_data)[0]
        R = []
        for _ in range(R_size):
            element_data = connection.recv(2)
            element = struct.unpack('!H', element_data)[0]
            R.append(element)

        self.R = R

        return tuples, R

    # 返回响应mu, 处理标签sigma, 需要从文件中读入来保证正确存储+正确复制
    def server_Response(self):

        # 路径
        folder = 'file_folder'
        file_name = 'D_file.txt' 
        replica_name = 'r_file.txt'
        
        D_file = None
        r_D_file = None

        # 从文件中读入D文件
        file_path = os.path.join(folder, file_name)
        with open(file_path, 'r') as file:
            file_content = file.read()

            file_content_with_comma = file_content.replace("\n  ", ", ")
            file_content_comma = file_content_with_comma.replace("\n ", ", ")
            
            D_list = eval(file_content_comma)
            D_file = np.array(D_list)

        # 从文件中读入文件副本
        replica_path = os.path.join(folder, replica_name)
        with open(replica_path, 'r') as file:
            file_content = file.read()

            file_content_with_comma = file_content.replace("\n  ", ", ")
            file_content_comma = file_content_with_comma.replace("\n ", ", ")
            
            r_D_list = eval(file_content_comma)
            # print(r_D_list)

            r_D_file = np.array(r_D_list)

        # 生成mu
        mu = []

        for i in range(self.s):
            temp_mu = 1

            for item in self.tuples:
                # temp_mu *= pow(D_file[item[0]-1][i], item[1], self.N)
                temp_mu = gmpy2.mul(temp_mu, gmpy2.powmod(D_file[item[0]-1][i], item[1], self.N))
            mu.append(temp_mu)
        
        # 处理sigma
        sigma = 1

        for item in self.tuples:
            c_index = item[0] - 1

            temp_multi = 1
            for j in range(self.s):
                for lil_R in self.R:
                    temp_multi *= r_D_file[lil_R-1][c_index][j]
                    temp_multi = temp_multi
            # sigma *= pow(self.sigma_list[c_index]*temp_multi, item[1], self.N)
            sigma = gmpy2.mul(sigma, gmpy2.powmod(self.sigma_list[c_index]*temp_multi, item[1], self.N))
            
        return mu, sigma

    # 发送响应及标签
    def Send_Response(self, mu, sigma, client_socket):

        try:
            # 打包mu列表
            mu_length = len(mu)
            packed_data = struct.pack("!I", mu_length)
            for i in range(mu_length):
                mu_str = str(mu[i])
                mu_bytes = mu_str.encode()
                packed_data += struct.pack("!I", len(mu_bytes))
                packed_data += mu_bytes

            # 打包sigma
            sigma_str = str(sigma)
            sigma_bytes = sigma_str.encode()
            sigma_len = len(sigma_bytes)
            packed_data += struct.pack('!I', sigma_len)

            packed_data += sigma_bytes

            # print(packed_data)
            # 发送数据
            client_socket.sendall(packed_data)
            

        except Exception as e:
            print("[ERROR]: ", e)

        finally:
            # 关闭连接
            client_socket.close()

        pass
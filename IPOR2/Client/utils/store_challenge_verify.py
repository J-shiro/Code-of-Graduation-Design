import os
import math
import random
import sys
import struct
import socket
import secrets
import time
import gmpy2
import asyncio
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from Crypto.Util.number import inverse
from reedsolo import RSCodec
from Crypto.Util.number import getStrongPrime
import numpy as np
from collections import OrderedDict

from utils import lfsr

sys.set_int_max_str_digits(10000)

class SCV:
    # 初始化
    def __init__(self, kappa=512, s=20, nambda=5, m=5, l=3, r=6, key=b'\xd6\xc1\xb2P\xe5\xe1\xcc\xe5\x16<t\x90[\x9cb\x93'):
        self.kappa = kappa
        self.s = s
        self.nambda = nambda
        self.l = l      # 挑战的元素
        self.r = r      # 副本数量
        self.N = 0      # 初始值
        self.n = 0      # 初始值
        self.key = key  # 对称加密的密钥
        self.m = m      # 纠错编码长度
        self.p = 0
        self.q = 0
        self.p_prime = 0
        self.q_prime = 0
        self.Phi_n = 0
        self.g = 0
        self.h = 0
        self.k_prf = None

        self.u = None   # Z_N^*的高阶元素

        self.sk = None
        
        self.D_file = None

        self.ga = None
        self.hb = None
        self.a = None
        self.b = None

        self.alpha = None
        self.beta = None 
        self.alpha_prime = None
        self.beta_prime = None
        self.epsilon = None

        self.ini_ga = None
        self.ini_hb = None

        self.S = None

    # 获取文件二进制流
    def get_file_stream(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                D = file.read()

            return D
        except Exception as e:
            print("ERROR: ", e)

    # 产生对称密钥
    def Create_key(self):
        key = secrets.token_bytes(16)
        return key

    # 对称加密 D
    def Enc_D(self, D):
        # 16字节随机IV
        iv = os.urandom(16)

        # AES加密器创建
        AES_cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv),backend=default_backend())
        AES_encryptor = AES_cipher.encryptor()

        # 加密D
        enc_D = iv + AES_encryptor.update(D) + AES_encryptor.finalize() # 最后一个加密

        return enc_D

    # 对称解密 D
    def Dec_D(self, enc_D):
        # 提取IV
        iv = enc_D[:16]
        
        # AES解密器创建
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # 解密D
        dec_D = decryptor.update(enc_D[16:]) + decryptor.finalize()
        
        return dec_D

    # 纠删码对文件进行处理
    def Encode_ec_D(self, data):
        '''
            m: 校验块数
            data: 数据文件
        ''' 
        # 定义纠删码对象
        rs = RSCodec(self.m)

        ec_data = rs.encode(data)
        return ec_data

    # 解纠删码
    def Decode_ec_D(self, ec_data):
        # 定义纠删码对象
        rs = RSCodec(self.m)

        # 解码数据, 返回原数据，原纠删码处理后数据，检测错误发生的位置
        raw_data, reconstructed_data, error_num = rs.decode(ec_data)

        return raw_data, reconstructed_data, error_num

    # 生成生成元g
    def find_generator(self, p, q):
        N = p * q
        p_prime = (p - 1) // 2
        q_prime = (q - 1) // 2

        # 选择一个随机数作为候选生成元
        g_candidate = random.randint(2, N - 1)

        # 计算 g = g_candidate^((p-1)/2) mod p
        g = gmpy2.powmod(g_candidate, p_prime, N)
        # g = pow(g_candidate, p_prime, N)
        if g == 1:
            # 如果 g = 1 mod N，尝试 g_candidate^((p-1)/2q) mod p
            # g = pow(g_candidate, p_prime // q_prime, N)
            g = gmpy2.powmod(g_candidate, p_prime // q_prime, N)
            if g == 1:
                return None
        
        return g

    # 生成模N的order阶的生成元h
    def Generate_element(self, order, N, generator):
        # 找到具有阶为order的元素h，即 h = g^((p-1)/2q) mod N
        # h = pow(generator, (N - 1) // (2 * order), N)
        h = gmpy2.powmod(generator, (N - 1) // (2 * order), N)
        return h

    # 定义PRF函数PHI(): 输入相同的值，会获得相同的整型内容
    def PHI_prf_sk(self, i):

        ans_bytes = hmac.new(self.sk, i.to_bytes((i.bit_length() + 7) // 8, 'big'), hashlib.sha256).digest()
        ans = int.from_bytes(ans_bytes, byteorder="big")

        return ans

    # 寻找生成元g
    def find_g(self):
        for g in range(2, self.N):
            if pow(g, (self.N - 1) // 2, self.N) != 1 and pow(g, (self.N - 1) // 3, self.N) != 1:
                return g
        return None

    # 生成高阶元素u
    def Generate_u_element(self):
        generator = self.find_g()
        if generator is None:
            print("未找到 Z_{}* 的生成元".format(self.N))
            return None
        while True:
            u = random.randint(2, self.N - 1)
            if pow(generator, u, self.N) != 1:
                self.u = u
                return u

    # 构建RSA模量N
    def init_param(self, byte_file):
        # 生成伪随机密钥k_prf
        k_prf = os.urandom(self.kappa // 8)
        self.k_prf = k_prf

        # 生成密钥sk
        sk = os.urandom(self.kappa // 8)
        self.sk = sk

        # 生成两个安全质数p和q，大小由kappa选择
        p = getStrongPrime(self.kappa)
        q = getStrongPrime(self.kappa)
        self.p = p
        self.q = q

        # 计算初始变量
        N = p*q
        self.N = N
        Phi_n = (p-1)*(q-1)
        p_prime = (p-1) // 2
        q_prime = (q-1) // 2

        self.p_prime = p_prime
        self.q_prime = q_prime
        self.Phi_n = Phi_n

        # 求块数n
        n = math.ceil(len(byte_file)*8 / (self.s * math.log10(N)))
        self.n = n

        # 生成 g 和 h
        generator = self.find_generator(p, q)
        g = self. Generate_element(p_prime, N, generator)
        h = self.Generate_element(q_prime, N, generator)

        self.g = g
        self.h = h

        # 生成u
        u = self.Generate_u_element()

        return k_prf, N, Phi_n, p, q, n, p_prime, q_prime, g, h

    # 生成特征模式
    def Generate_pattern(self, byte_file):
        # 文件大小, 单位: byte
        file_size = len(byte_file)

        # 特征模式长度
        pattern_length = math.ceil(math.log2(self.n * self.s))

        # 生成特征模式序列
        pattern = '0' * pattern_length
        return pattern

    # 生成上传给服务器的D
    def file_stream_2_matrix(self, byte_file):
        '''
            byte_file: 字节流文件
            s: 扇区数
            N: 模量
        '''
        # 文件大小, 单位: byte
        file_size = len(byte_file)

        # 单个扇区的大小
        sector_size = len(byte_file) // (self.n * self.s)

        # 初始化矩阵
        matrix = []

        # 生成特征模式序列
        pattern = self.Generate_pattern(byte_file)

        # 分割文件为n个块, 每个块s个扇区, 并将每个扇区转换为 Z_N 中的整数
        for i in range(self.n):
            block = []
            for j in range(self.s):
                # 索引计算
                start_index = (i * self.s + j) * sector_size
                end_index = min((i * self.s + j + 1) * sector_size, file_size)

                # 取字节文件值, 转换为整数, 取模N
                sector_data = byte_file[start_index:end_index]
                sector_integer = int.from_bytes(sector_data, byteorder='big') % self.N

                # 在每个扇区的值后添加特征模式
                sector_integer_with_pattern = int(str(sector_integer) + pattern)
                block.append(sector_integer_with_pattern)

            matrix.append(block)
        
        # 二维列表转换为矩阵
        D_matrix = np.array(matrix)

        self.D_file = D_matrix
        
        return D_matrix

    # 获取非0 epsilon序列
    def sample_nonzero_elements(self):
        # 随机种子,使用k_prf, 长度kappa
        random.seed(self.k_prf)
        
        # Z_Phi_N 随机采样的非零元素, 键值对存储
        s_epsilon = OrderedDict()

        while len(s_epsilon) < self.s:
            element = random.randint(1, self.Phi_n) # 随机生成一个非零元素
            s_epsilon[element] = 1
        
        s_epsilons = list(s_epsilon.keys())

        self.epsilon = s_epsilons

        # 返回epsilon列表
        return s_epsilons

    # 生成验证: n个sigma
    def Generate_Verify_sigma(self, s_epsilon, D_matrix):

        sigma_list = [1 for _ in range(self.n)]

        # 计算校验值
        for i in range(self.n):
            for j in range(self.s):
                # 使用gmpy2更快计算大整数模运算
                D_pow = gmpy2.powmod(D_matrix[i, j], s_epsilon[j], self.N)
                sigma_list[i] = gmpy2.mul(sigma_list[i], D_pow) % self.N
            
            sigma_list[i] = gmpy2.mul(sigma_list[i], gmpy2.powmod(self.u, self.PHI_prf_sk(i+1), self.N))
            #     sigma_list[i] *= pow(D_matrix[i, j], s_epsilon[j], self.N)
            # sigma_list[i] %= self.N
        return sigma_list

    # 生成四个序列： a, g^a, b, h^b, alpha, alpha_prime, beta, beta_prime
    # 其中a, b, g^a, h^b 均需要最后获得矩阵
    def Generate_from_LFSR(self):

        # 获取lfsr的实例
        lfsr_s = lfsr.LFSR()

        # 获取系数
        alpha, alpha_prime = lfsr_s.Create_coefficients(self.nambda)
        beta, beta_prime = lfsr_s.Create_coefficients(self.nambda)

        self.alpha = alpha
        self.beta = beta
        self.alpha_prime = alpha_prime
        self.beta_prime = beta_prime

        # 初始化6个二维列表
        ini_a_stat = []
        a_final_secret = []
        a_final_public = []
        ini_b_stat = []
        b_final_secret = []
        b_final_public = []

        # 初始化传输给服务器的r个副本所需的各自的ga和hb的初始状态
        ga_ini_to_server = []
        hb_ini_to_server = []
        
        # 生成
        for _ in range(self.r):
            ini_a_stat_tmp, a_final_secret_tmp, a_final_public_tmp = lfsr_s.Process_LFSR(self.nambda, self.n * self.s, self.p_prime, self.g, alpha, alpha_prime, self.N)
            ini_a_stat.append(ini_a_stat_tmp)
            a_final_secret.append(a_final_secret_tmp)
            a_final_public.append(a_final_public_tmp)
            ga_ini_to_server.append(a_final_public_tmp[0:2*self.nambda])
        
        for _ in range(self.r):
            ini_b_stat_tmp, b_final_secret_tmp, b_final_public_tmp = lfsr_s.Process_LFSR(self.nambda, self.n*self.s, self.q_prime, self.h, beta, beta_prime, self.N)
            ini_b_stat.append(ini_b_stat_tmp)
            b_final_secret.append(b_final_secret_tmp)
            b_final_public.append(b_final_public_tmp)
            hb_ini_to_server.append(b_final_public_tmp[0:2*self.nambda])

        # 实际传递给服务器的只是ga和hb的初始状态
        # 其为r * (2*nambda) 的列表
        ga_ini_to_server = np.array(ga_ini_to_server)
        hb_ini_to_server = np.array(hb_ini_to_server)

        ini_a_stat = np.array(ini_a_stat)
        a_final_secret = np.array(a_final_secret)
        a_final_public = np.array(a_final_public)
        ini_b_stat = np.array(ini_b_stat)
        b_final_secret = np.array(b_final_secret)
        b_final_public = np.array(b_final_public)

        self.a = a_final_secret
        self.b = b_final_secret
        self.ga = a_final_public
        self.hb = b_final_public

        # print(self.ga)

        self.ini_ga = ga_ini_to_server
        self.ini_hb = hb_ini_to_server

        # 生成的ga和hb是包含 r个，每个是n*s的矩阵

        return ini_a_stat, alpha, alpha_prime, a_final_secret, a_final_public,ini_b_stat, beta, beta_prime, b_final_secret, b_final_public, ga_ini_to_server, hb_ini_to_server

    # 生成四个序列： a, g^a_ini, b, h^b_ini, alpha, alpha_prime, beta, beta_prime
    def Generate_using_LFSR(self):

        # 获取lfsr的实例
        lfsr_s = lfsr.LFSR()

        # 获取系数
        alpha, alpha_prime = lfsr_s.Create_coefficients(self.nambda)
        beta, beta_prime = lfsr_s.Create_coefficients(self.nambda)

        self.alpha = alpha
        self.beta = beta
        self.alpha_prime = alpha_prime
        self.beta_prime = beta_prime

        # 初始化6个二维列表
        ini_a_stat = []
        ini_b_stat = []


        # 初始化传输给服务器的r个副本所需的各自的ga和hb的初始状态
        ga_ini_to_server = []
        hb_ini_to_server = []
        
        # 生成
        for _ in range(self.r):
            ini_a_stat_tmp, a_final_secret_tmp, a_final_public_tmp = lfsr_s.Process_LFSR(self.nambda, self.n * self.s, self.p_prime, self.g, alpha, alpha_prime, self.N)
            ini_a_stat.append(ini_a_stat_tmp)
            a_final_secret.append(a_final_secret_tmp)
            a_final_public.append(a_final_public_tmp)
            ga_ini_to_server.append(a_final_public_tmp[0:2*self.nambda])
        
        for _ in range(self.r):
            ini_b_stat_tmp, b_final_secret_tmp, b_final_public_tmp = lfsr_s.Process_LFSR(self.nambda, self.n*self.s, self.q_prime, self.h, beta, beta_prime, self.N)
            ini_b_stat.append(ini_b_stat_tmp)
            b_final_secret.append(b_final_secret_tmp)
            b_final_public.append(b_final_public_tmp)
            hb_ini_to_server.append(b_final_public_tmp[0:2*self.nambda])

        # 实际传递给服务器的只是ga和hb的初始状态
        # 其为r * (2*nambda) 的列表
        ga_ini_to_server = np.array(ga_ini_to_server)
        hb_ini_to_server = np.array(hb_ini_to_server)

        ini_a_stat = np.array(ini_a_stat)
        a_final_secret = np.array(a_final_secret)
        a_final_public = np.array(a_final_public)
        ini_b_stat = np.array(ini_b_stat)
        b_final_secret = np.array(b_final_secret)
        b_final_public = np.array(b_final_public)

        self.a = a_final_secret
        self.b = b_final_secret
        self.ga = a_final_public
        self.hb = b_final_public

        # print(self.ga)

        self.ini_ga = ga_ini_to_server
        self.ini_hb = hb_ini_to_server

        # 生成的ga和hb是包含 r个，每个是n*s的矩阵

        return ini_a_stat, alpha, alpha_prime, a_final_secret, a_final_public,ini_b_stat, beta, beta_prime, b_final_secret, b_final_public, ga_ini_to_server, hb_ini_to_server

    # 发起挑战，关于随机采样非零子集 R 的 s-1 个扇区进行验证是否完整存储而不是存储乘积
    def random_s_challenge(self):

        r = int(input("选择需要验证的副本: "))
        if r <= 0 or r > self.r:
            print("副本一共只有", self.r, "个, 请重新选择")
            return
        
        n = int(input("选择需要验证的块号: "))
        if n <= 0 or n > self.n:
            print("块数一共只有", self.n, "个, 请重新选择")
            return

        v_s = []
        
        # 生成s-1个随机的数在范围1-s中间
        v_s = sorted(random.sample(range(1, self.s+1), self.s - 1))
    
        return r, n, v_s

    async def Send_random_s_challenge(self, r, n, v_s):
        # 套接字连接服务器
        reader, writer = await asyncio.open_connection('localhost', 15323)

        # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # server_address = ('localhost', 15323)
        # client_socket.connect(server_address)

        try:
            # 打包索引6
            packed_data = struct.pack("!I", 6)

            # 打包r, n, v_s
            packed_data += struct.pack('iii' + 'B'*len(v_s), r, n, len(v_s), *v_s)

            # 发送数据
            writer.write(packed_data)

            print("[Challenge]: 发送完成!!\n")

            # 接收服务器的响应
            s_size_data = await reader.read(4)

            s_size = struct.unpack('!I', s_size_data)[0]

            s = []
            for _ in range(s_size):
                each_s_size_bytes = await reader.read(4)
                each_s_size = struct.unpack('!I', each_s_size_bytes)[0]

                element = b''
                while len(element) < each_s_size:
                    element += await reader.read(each_s_size - len(element))

                element = int(element)
                s.append(element)

            num, right_num = 0, 0
            # 验证是否正确存储每个扇区
            for i in v_s:
                x = (n-1)*self.s+i-1 # x为矩阵平摊为一维时的正顺序

                si = self.D_file[n-1][i-1] * self.ga[r-1][x] * self.hb[r-1][self.n*self.s - (x+1)]

                if si == s[num]:
                    right_num += 1
                num += 1
            
            print("[Verify]: 验证扇区完成, 完整存储了", right_num, "个扇区(共", self.s-1, "个)\n")

        except Exception as e:
            print("[ERROR]: ", e)

        finally:
            # 关闭连接
            writer.close()
            await writer.wait_closed()



    # 发起随机挑战C
    def random_Challenge(self):
        '''
            生成l个元组(i, v_i)
            i: 1-n
            v_i: in Z_N
        '''
        # 随机抽取 l 个不重复的索引 i
        indices = random.sample(range(1, self.n+1), self.l)
        tuples = [(i, random.randint(0, self.N-1)) for i in indices]

        # 随机采样非零子集 R param: 总体, 样本数量
        R = set(random.sample(range(1, self.r+1), random.randint(1, self.r)))
        print("[Verify]: 验证选取的副本包括", R)

        # 生成 S , 从1-s中随机取[随机]个元素, 后续证明s-1为效果最好
        S = sorted(random.sample(range(1, self.s+1), random.randint(1, self.s - 1)))
        self.S = S
        print("[Verify]: 验证选取的扇区包括", S)

        return tuples, R, S

    '''
        发送数据需要调整, 需要加入发送的索引
        若为数据及验证标签: 2
        若为挑战: 3

        接收数据只有服务器的响应, 即不需要索引
    '''
    # 将数据一并打包发送给服务器
    def Send_Tag_and_File(self, D_file, ga, hb, alpha_prime, beta_prime, sigma_list):

        # 套接字连接服务器
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 15323)
        client_socket.connect(server_address)

        try:
            # 打包索引2
            packed_data = struct.pack("!I", 2)
            
            # 打包文件

            # 打包N
            N_str = str(self.N)
            N_bytes = N_str.encode()
            packed_data += struct.pack("!I", len(N_bytes))
            packed_data += N_bytes
            print("[Store]: N packed")
            # 打包文件矩阵shape的行列
            f_row, f_col = D_file.shape # (4, 20)
            packed_data += struct.pack("!II", f_row, f_col)
            file_str = ''.join(str(elem) for elem in D_file.flatten())
            file_bytes = file_str.encode()

            packed_data += struct.pack("!I", len(file_bytes)) # 文件总字节的长度

            for i in range(f_row):
                for j in range(f_col):
                    each_D_str = str(D_file[i, j])
                    each_D_str_bytes = each_D_str.encode()
                    packed_data += struct.pack("!I", len(each_D_str_bytes)) # file_D中每个大整数长度
                    packed_data += each_D_str_bytes

            print("[Store]: D_file packed")
            # 打包sigma序列
            sigma_strlist_tmp = ''

            for sigma in sigma_list:
                sigma_strlist_tmp += str(sigma)
            len_sigma_str_list = len(sigma_strlist_tmp)
            packed_data += struct.pack("!I", len_sigma_str_list) # 整个sigma字符串的大小

            for sigma in sigma_list:
                sigma_strlist = str(sigma)
                sigma_bytes = sigma_strlist.encode()
                packed_data += struct.pack("!I", len(sigma_bytes)) # 每一段的字符串长度
                packed_data += sigma_bytes
            print("[Store]: sigma_list packed")

            # 实际应该为打包初始的ga和hb矩阵而不是最终的ga和hb矩阵
            # # 打包ga和hb矩阵shape的行列
            # row, col = ga.shape # (4, 80)
            # packed_data += struct.pack("!II", row, col)

            # # 打包ga和hb矩阵

            # # 将数组中元素转换为字符串
            # ga_str = ''.join(str(elem) for elem in ga.flatten())
            # hb_str = ''.join(str(elem) for elem in hb.flatten())

            # # 编码为字节序列
            # ga_bytes = ga_str.encode()
            # hb_bytes = hb_str.encode()

            # packed_data += struct.pack("!I", len(ga_bytes)) # ga字节的长度

            # for i in range(row):
            #     for j in range(col):
            #         each_str = str(ga[i, j])
            #         each_str_bytes = each_str.encode()
            #         packed_data += struct.pack("!I", len(each_str_bytes)) # ga中每个大整数长度
            #         packed_data += each_str_bytes
            # print("[Store]: ga packed")
            # packed_data += struct.pack("!I", len(hb_bytes)) # hb字节的长度

            # for i in range(row):
            #     for j in range(col):
            #         each_str = str(hb[i, j])
            #         each_str_bytes = each_str.encode()
            #         packed_data += struct.pack("!I", len(each_str_bytes)) # hb中每个大整数长度
            #         packed_data += each_str_bytes
            # print("[Store]: hb packed")

            # 打包ga和hb矩阵shape的行列
            row, col = ga.shape # (r, 2*nambda)
            packed_data += struct.pack("!II", row, col)

            # 打包ga和hb矩阵

            # 将数组中元素转换为字符串
            ga_str = ''.join(str(elem) for elem in ga.flatten())
            hb_str = ''.join(str(elem) for elem in hb.flatten())

            # 编码为字节序列
            ga_bytes = ga_str.encode()
            hb_bytes = hb_str.encode()

            packed_data += struct.pack("!I", len(ga_bytes)) # ga字节的长度

            for i in range(row):
                for j in range(col):
                    each_str = str(ga[i, j])
                    each_str_bytes = each_str.encode()
                    packed_data += struct.pack("!I", len(each_str_bytes)) # ga中每个大整数长度
                    packed_data += each_str_bytes
            print("[Store]: ga packed")
            packed_data += struct.pack("!I", len(hb_bytes)) # hb字节的长度

            for i in range(row):
                for j in range(col):
                    each_str = str(hb[i, j])
                    each_str_bytes = each_str.encode()
                    packed_data += struct.pack("!I", len(each_str_bytes)) # hb中每个大整数长度
                    packed_data += each_str_bytes
            print("[Store]: hb packed")

            # 打包sk
            sk_len = len(self.sk)
            packed_data += struct.pack('!I', sk_len)

            packed_data += self.sk
            print("[Store]: sk packed")

            # 打包u
            u_str = str(self.u)
            u_bytes = u_str.encode()
            u_len = len(u_bytes)
            packed_data += struct.pack('!I', u_len)

            packed_data += u_bytes
            print("[Store]: u packed")

            # 打包两个验证列表
            packed_data += struct.pack(f"!{len(alpha_prime)}I", *alpha_prime)
            packed_data += struct.pack(f"!{len(beta_prime)}I", *beta_prime)
            print("[Store]: alpha_beta_prime packed")



            # 发送打包后的数据
            client_socket.sendall(packed_data)

        except Exception as e:
            print("[ERROR]: ", e)

        finally:
            # 关闭连接
            client_socket.close()

    # 将挑战打包发送给服务器, 接收服务端响应, 并进行验证
    def Send_Challenge_Receive_Response_Verify(self, tuples, R, S):
        # 套接字连接服务器
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 15323)
        client_socket.connect(server_address)

        try:
            # 打包索引3
            packed_data = struct.pack("!I", 3)

            # 打包元组
            tuples_length = len(tuples)
            packed_data += struct.pack("!I", tuples_length)
            for i in range(tuples_length):
                packed_data += struct.pack("!I", tuples[i][0])
                v_i_str = str(tuples[i][1])
                v_i_bytes = v_i_str.encode()
                packed_data += struct.pack("!I", len(v_i_bytes))
                packed_data += v_i_bytes

            # 打包r的子集R
            R_size = len(R)
            packed_data += struct.pack('!I', R_size)

            # 打包集合R中的每个元素
            for element in R:
                packed_data += struct.pack('!H', element)

            # 打包S
            packed_data += struct.pack('i' + 'B'*len(S), len(S), *S)

            # 发送数据
            client_socket.sendall(packed_data)

            print("[Challenge]: 发送完成!!\n")

            # 接收服务端的响应mu
            mu_size_data = client_socket.recv(4)
            mu_size = struct.unpack('!I', mu_size_data)[0]

            mu = []
            for _ in range(mu_size):
                each_mu_size_bytes = client_socket.recv(4)
                each_mu_size = struct.unpack('!I', each_mu_size_bytes)[0]

                element = b''
                while len(element) < each_mu_size:
                    element += client_socket.recv(each_mu_size - len(element))

                element = int(element)
                mu.append(element)
            
            # 接收服务端的响应sigma
            sigma_size_data = client_socket.recv(4)
            sigma_size = struct.unpack('!I', sigma_size_data)[0]

            sigma = b''
            while len(sigma) < sigma_size:
                sigma += client_socket.recv(sigma_size - len(sigma))
            sigma = int(sigma)

            # 验证
            # 倒置hb
            hb_list = []

            for sub_hb in self.hb:
                # 对每个子数组进行倒置操作
                inverted_array = np.flip(sub_hb)
                hb_list.append(inverted_array)
            
            # 将列表转换为 ndarray
            hb_result_list = np.array(hb_list)
            hb_3d_matrix = hb_result_list.reshape(self.r, self.n, self.s)
            
            # 处理ga为3维
            ga_3d_matrix = self.ga.reshape(self.r, self.n, self.s)

            # 计算sigma_prime, 即等式左边
            temp = 1

            for item in tuples:
                c_index = item[0] - 1

                temp_multi = 1
                for j in self.S:
                    for lil_R in R:
                        temp_multi *= ga_3d_matrix[lil_R-1][c_index][j-1]*hb_3d_matrix[lil_R-1][c_index][j-1]
                        temp_multi = temp_multi % self.N

                # temp *= pow(temp_multi, item[1]*(-1), self.N)
                temp = gmpy2.mul(temp, gmpy2.powmod(temp_multi, item[1]*(-1), self.N))

            sigma_prime = temp*sigma % self.N
            # print("right: ", sigma_prime)


            # 计算等式右边
            left_result = 1

            # 第一个值
            left_result_1 = 1
            for c in range(len(tuples)):
                left_result_1 = gmpy2.mul(left_result_1, gmpy2.powmod(self.u, gmpy2.mul(self.PHI_prf_sk(tuples[c][0]), tuples[c][1]), self.N))
            
            # 第二个值
            left_result_2 = 1

            for j in S:
                # left_result *= pow(mu[j], self.epsilon[j]+len(R), self.N)
                left_result_2 = gmpy2.mul(left_result_2, gmpy2.powmod(mu[j-1], self.epsilon[j-1]+len(R), self.N))
            left_result_2 = left_result_2 % self.N

            # 第三个值
            left_result_3 = 1

            fS = []
            for i in range(self.s):
                if i+1 not in S:
                    fS.append(i+1)

            for j in fS:
                left_result_3 = gmpy2.mul(left_result_3, gmpy2.powmod(mu[j-1], self.epsilon[j-1], self.N))

            # 右边结果
            left_result =  gmpy2.mul(left_result_1, gmpy2.mul(left_result_2, left_result_3)) % self.N

            # print(sigma_prime == left_result)
            return sigma_prime == left_result

        except Exception as e:
            print("[ERROR]: ", e)

        finally:
            # 关闭连接
            client_socket.close()
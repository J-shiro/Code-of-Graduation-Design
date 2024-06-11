import random
import gmpy2

class LFSR:
    def __init__(self) -> None:
        pass

    # 生成LFSR的系数
    def Generate_coefficients(self, lambda_val, max_coefficient=1000):
        coefficients = [random.randint(0, max_coefficient) for _ in range(lambda_val)]
        return coefficients

    # 生成某个块的初始LSFR序列
    def Generate_ini_state(self, lambda_leng, prime_pq):
        '''
            lambda_value: LFSR长度
            prime_pq: 阶
        '''
        initial_state = []

        # 生成lambda个随机值
        for _ in range(lambda_leng):
            initial_state.append(random.randint(0, prime_pq-1))
        
        return initial_state

    # # 对初始序列进行LFSR, 生成最终序列长度
    # def secret_LSFR(self, ini_array, c_array, s, ord):
    #     '''
    #         ini_array: 初始状态序列
    #         c_array: 系数
    #         s: 生成最终序列的长度
    #         ord: 阶
    #     '''
    #     leng = len(ini_array)
    #     fini_array = ini_array[:]

    #     for it in range(leng, s):

    #         new_value = 0
    #         num = 0 # 遍历c系数序列

    #         for i in range(it-leng, it):
    #             new_value += fini_array[i]*c_array[num]
    #             num += 1

    #         new_value = new_value % ord
        
    #         fini_array.append(new_value)

    #     return fini_array

    def public_LSFR(self, ini_array, c_array, s, ord, g):
        leng = len(ini_array)
        # fini_array = [pow(g, x, ord) for x in ini_array]
        fini_array = [gmpy2.powmod(g, x, ord) for x in ini_array]

        for it in range(leng, s):

            new_value = 1
            num = 0 # 遍历c系数序列

            for i in range(it-leng, it):
                # new_value *= pow(pow(g, fini_array[i], ord) , c_array[num], ord)
                new_value = gmpy2.mul(new_value, gmpy2.powmod(fini_array[i], c_array[num], ord))
                num += 1

            new_value = gmpy2.f_mod(new_value, ord)
            # new_value = new_value % ord
        
            fini_array.append(new_value)

        return fini_array

    # 通过反馈多项式的计算获取倍数多项式的系数c_prime
    def c2c_prime(self, c_array):
        '''
            输入为c_1, c_2, ..., c_lambda
            实际多项式为: -c_1, -c_2, ..., -c_lambda, 1
        '''

        poly1 = [-x for x in c_array]
        poly1.append(1)
        poly2 = [x//2 for x in c_array]
        poly2.append(1)
        # print(poly2)

        # 计算乘积多项式的次数
        deg = len(poly1)*2 - 2

        c_prime_array = [0]* (deg + 1)

        # 计算乘积多项式的系数
        for i in range(len(poly1)):
            for j in range(len(poly2)):
                c_prime_array[i + j] += poly1[i] * poly2[j]

        c_prime_array = [-x for x in c_prime_array[:-1]]

        return c_prime_array

    # 生成nambda个系数alpha, 以及2*nambda个系数beta
    def Create_coefficients(self, nambda):
        coefficient = self.Generate_coefficients(nambda)
        coefficient_prime = self.c2c_prime(coefficient)

        return coefficient, coefficient_prime

    # 使用LFSR生成标签
    def Process_LFSR(self, nambda, final_stat_length, ord, generator,c, c_prime):
        '''
            会生成后续需要的g^a, h^b(public), 以及a, b(secret)
        '''
        ini_nambda_stat = self.Generate_ini_state(nambda, ord)

        final_stat_secret = self.secret_LSFR(ini_nambda_stat, c, final_stat_length, ord)

        final_stat_public = self.public_LSFR(final_stat_secret[0:2*nambda], c_prime, final_stat_length, ord, generator)

        return ini_nambda_stat, final_stat_secret, final_stat_public

    # 使用ga的初始列计算后续的完整的ga序列
    def public_lfsr_with_no_g(self, ini_ga_hb, n_s, c_array, N):
        leng = len(ini_ga_hb)

        fini_array = ini_ga_hb[:].tolist()

        for it in range(leng, n_s):

            new_value = 1
            num = 0 # 遍历c系数序列

            for i in range(it-leng, it):
                new_value = gmpy2.mul(new_value, gmpy2.powmod(fini_array[i], c_array[num], N))
                num += 1

            new_value = new_value % N

            fini_array.append(int(new_value))

        return fini_array
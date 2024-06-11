from utils import lfsr
from utils import store_challenge_verify as scv
import socket
import asyncio
import time

# 菜单
def menu():
    print("请选择操作：")
    print("1. 更新初始参数")
    print("2. 存储过程(Store)")
    print("3. 生成发送挑战(Challenge)及验证响应(Verify)")
    print("4. 多次挑战及验证")
    print("5. 退出")
    
    print("6. 验证s-1个扇区防止节省存储攻击") # 如果验证失败，则表明只存储了乘积μ存储所有扇区值
                                            # 相应要制造服务器伪造一个文件存储各副本的乘积的文件

async def main():
    # 初始化实例
    user = scv.SCV()
    print("\n[Notice]: 创建实例完成...\n")
    
    while True:
        menu()
        choice = input("请输入选项编号：")
            
        if choice == "1":
            user = U_param_update(user) # 更新参数
            print("\n[Notice]: 更新参数成功...\n")

        elif choice == "2": # 存储并发送给服务器验证标签
            U_Store(user)
            
        elif choice == "3": # 发起挑战并接受响应，对响应进行验证
            U_Challenge_Verify(user)

        elif choice == "4": # 发起多个挑战，获取成功概率
            n = int(input("请求挑战次数: "))
            success_num = U_multi_Challenge_Verify(user, n)
            print("验证成功概率: {:.2f}%".format((success_num / n) * 100), "  [", success_num, "/", n, "]")

        elif choice == "6": # 改善POR2, 防止节省存储攻击
            await U_Verify_sector(user)

        elif choice == "5":
            print("[Mirror]: 退出程序成功!")
            break
        else:
            print("无效选项，请重新输入!!")

# 之后可用于修改初始参数
def U_param_update(user):

    kappa = input("kappa: ")
    s = input("s: ")
    nambda = input("nambda: ")
    m = input("m: ")
    l = input("l: ")
    r = input("r: ")
    
    key = user.Create_key()

    return scv.SCV(kappa=kappa, s=s, nambda=nambda, m=m, l=l, r=r, key=key)

def U_Store(user):

    # D = user.get_file_stream("./D.txt")
    file_path = input("请输入准备存储的文件: ")
    # D = user.get_file_stream("./generated_2mb_file.txt")
    D = user.get_file_stream("./"+str(file_path))

    # 开始计时
    out_start_time = time.time()

    # D = user.get_file_stream("./generated_2mb_file.txt")
    enc_D=user.Enc_D(D)
    ec_D = user.Encode_ec_D(enc_D)
    k_prf, N, Phi_n, p, q, n, p_prime, q_prime, g, h = user.init_param(ec_D)
    split_D = user.file_stream_2_matrix(ec_D)
    epsilon = user.sample_nonzero_elements()
    sigma_list = user.Generate_Verify_sigma(epsilon, split_D)
    ini_a_stat, alpha, alpha_prime, a_final_secret, a_final_public,ini_b_stat, beta, beta_prime, b_final_secret, b_final_public, ini_ga, ini_hb = user.Generate_from_LFSR()
    
    
    out_end_time = time.time()
    time_run = out_end_time - out_start_time
    print("\n[Store]: 准备完成...")
    print("[Store]: -", file_path, "-耗时: ", time_run)
    print("[Store]: 准备发送...")

    # user.Send_Tag_and_File(split_D, a_final_public, b_final_public, alpha_prime, beta_prime, sigma_list)
    user.Send_Tag_and_File(split_D, ini_ga, ini_hb, alpha_prime, beta_prime, sigma_list)

    print("[Store]: 发送完成!!\n")

def U_Challenge_Verify(user):
    if user.n == 0:
        print("\n[ERROR]: 请先进行Store过程!!\n")
        return
    tuples, R, S = user.random_Challenge()

    print("\n[Challenge]: 准备完成...")
    print("[Challenge]: 准备发送...\n")

    ans = user.Send_Challenge_Receive_Response_Verify(tuples, R, S)
    if ans == True:
        print("\n[Verify]:[Yes] 验证成功, 服务器完整存储了文件及副本!")
    elif ans == False:
        print("[Verify]:[No] 验证成功, 服务器未完整存储文件及副本!!")

def U_each_Challenge_Verify(i, user):
    if user.n == 0:
        print("\n[ERROR]: 请先进行Store过程!!\n")
        return
    tuples, R, S = user.random_Challenge()

    print("\n[Challenge]", i, ": 准备完成...")
    print("[Challenge]", i, ": 准备发送...\n")

    ans = user.Send_Challenge_Receive_Response_Verify(tuples, R, S)
    if ans == True:
        return 1
    elif ans == False:
        return 0
    
# 扩展验证 (s-1) 个 sector
async def U_Verify_sector(user):
    r, n, v_s = user.random_s_challenge()
    await user.Send_random_s_challenge(r, n, v_s)

def U_multi_Challenge_Verify(user, count):
    
    # 计算成功次数
    success_num = 0
    for i in range(count):
        success_temp_num = U_each_Challenge_Verify(i, user)
        success_num += success_temp_num
    return success_num


if __name__ == "__main__":
    asyncio.run(main())

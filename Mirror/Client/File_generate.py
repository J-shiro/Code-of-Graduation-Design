import random
import string

def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_file_with_random_content(file_size):
    chunk_size = 1024  # 一次写入文件的块大小
    with open('generated_900kb_file.txt', 'w') as f:
        while file_size > 0:
            if file_size < chunk_size:
                chunk_size = file_size
            random_string = generate_random_string(chunk_size)
            f.write(random_string)
            file_size -= chunk_size

# 指定文件大小为 10MB（10 * 1024 * 1024 字节）
# file_size_in_bytes = 10 * 1024 * 1024
file_size_in_bytes = 900 * 1024

generate_file_with_random_content(file_size_in_bytes)

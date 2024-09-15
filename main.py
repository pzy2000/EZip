import os

os.environ['UNRAR_LIB_PATH'] = './unrar/unrar.dll'  # 设置 UNRAR 库路径
import sys
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import py7zr
from unrar import rarfile  # 使用 from unrar import rarfile
import pyzipper  # 用于加密的zip压缩
import zstandard as zstd  # 用于zstd压缩和解压缩
import atexit
import signal
import struct
from io import BytesIO

# 锁文件和临时文件路径，放置于脚本的同级目录
LOCK_FILE = 'smart_compress.lock'
TEMP_FILE = 'smart_compress_files.txt'
FILE_LOCK = 'file.lock'  # 自定义文件锁路径
LOCK_EXPIRY_SECONDS = 60  # 锁文件过期时间设置为60秒


def create_lock():
    """创建锁文件"""
    try:
        # 如果锁文件存在并且已经过期，则删除
        if os.path.exists(LOCK_FILE):
            if time.time() - os.path.getmtime(LOCK_FILE) > LOCK_EXPIRY_SECONDS:
                os.remove(LOCK_FILE)
                print("过期的锁文件已删除")

        if not os.path.exists(LOCK_FILE):
            with open(LOCK_FILE, 'w') as lock:
                lock.write(str(os.getpid()))
        return True
    except Exception as e:
        print(f"创建锁文件失败: {e}")
        return False


def is_main_instance():
    """检查是否是主实例，通过检测锁文件是否存在"""
    try:
        if os.path.exists(LOCK_FILE):
            with open(LOCK_FILE, 'r') as lock:
                pid = lock.read()
            # 检查是否有该PID进程在运行
            if pid and os.system(f"tasklist /FI \"PID eq {pid}\"") == 0:
                return False
        return create_lock()
    except Exception as e:
        print(f"检查锁文件失败: {e}")
        return False


def release_lock():
    """释放锁文件"""
    try:
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
            print("锁文件已释放")
    except Exception as e:
        print(f"释放锁文件失败: {e}")


# 确保锁文件在程序正常终止时被删除
atexit.register(release_lock)


# 捕获终止信号，确保锁文件被删除
def signal_handler(sig, frame):
    release_lock()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)  # 捕获 Ctrl+C 中断信号
signal.signal(signal.SIGTERM, signal_handler)  # 捕获终止信号


def acquire_file_lock(lock_path):
    """尝试获取文件锁"""
    while True:
        try:
            # 尝试创建锁文件，若存在则说明已被锁定
            if not os.path.exists(lock_path):
                with open(lock_path, 'w') as lock:
                    lock.write('lock')
                return True
        except Exception as e:
            print(f"获取文件锁失败: {e}")
        time.sleep(0.1)  # 等待一段时间后重试


def release_file_lock(lock_path):
    """释放文件锁"""
    try:
        if os.path.exists(lock_path):
            os.remove(lock_path)
    except Exception as e:
        print(f"释放文件锁失败: {e}")


def write_to_temp_file(file_paths):
    """将文件路径写入临时文件，保存最新的所有文件路径"""
    acquire_file_lock(FILE_LOCK)  # 获取文件锁
    try:
        with open(TEMP_FILE, 'a+') as temp_file:
            temp_file.seek(0)
            existing_paths = set(line.strip() for line in temp_file.readlines())
            temp_file.seek(0)
            temp_file.truncate()
            new_paths = set(file_paths)
            all_paths = existing_paths | new_paths
            for path in all_paths:
                temp_file.write(path + '\n')
    finally:
        release_file_lock(FILE_LOCK)  # 释放文件锁


def read_from_temp_file():
    """读取临时文件中的路径"""
    if not os.path.exists(TEMP_FILE):
        return []
    with open(TEMP_FILE, 'r') as temp_file:
        return [line.strip() for line in temp_file.readlines()]


def delete_temp_file():
    """删除临时文件"""
    try:
        if os.path.exists(TEMP_FILE):
            os.remove(TEMP_FILE)
            print(f"已删除临时文件：{TEMP_FILE}")
    except Exception as e:
        print(f"删除临时文件失败: {e}")


def update_file_progress(current, total):
    """更新文件数进度条"""
    file_progress['value'] = (current / total) * 100
    root.update_idletasks()


def update_block_progress(current, total):
    """更新块进度条"""
    block_progress['value'] = (current / total) * 100
    root.update_idletasks()


def unzip_file(zip_path, extract_path, pwd=None):
    # 确保提取路径存在
    if not os.path.exists(extract_path):
        os.makedirs(extract_path)

    password = pwd.encode() if pwd else None

    try:
        if zip_path.endswith('.zip'):
            with pyzipper.AESZipFile(zip_path, 'r', compression=pyzipper.ZIP_DEFLATED) as zip_ref:
                for file_info in zip_ref.infolist():
                    original_filename = file_info.filename
                    try:
                        file_info.filename = original_filename.encode('cp437').decode('utf-8')
                    except UnicodeDecodeError:
                        file_info.filename = original_filename
                    zip_ref.extract(file_info, path=extract_path, pwd=password)
            print(f"ZIP 文件已解压到：{extract_path}")
        elif zip_path.endswith('.7z'):
            with py7zr.SevenZipFile(zip_path, mode='r') as archive:
                archive.extractall(path=extract_path)
            print(f"7z 文件已解压到：{extract_path}")
        elif zip_path.endswith('.rar'):
            with rarfile.RarFile(zip_path) as rf:
                rf.extractall(path=extract_path)
            print(f"RAR 文件已解压到：{extract_path}")
        elif zip_path.endswith('.zst'):
            # 解压多文件 zst
            with open(zip_path, 'rb') as ifh:
                dctx = zstd.ZstdDecompressor()
                with dctx.stream_reader(ifh) as reader:
                    while True:
                        # 读取文件头信息
                        file_header = reader.read(8)
                        if not file_header:
                            break
                        # 读取文件名长度和文件内容长度
                        filename_len, file_size = struct.unpack('<II', file_header)
                        filename = reader.read(filename_len).decode('utf-8')
                        file_data = reader.read(file_size)
                        output_file = os.path.join(extract_path, filename)
                        with open(output_file, 'wb') as ofh:
                            ofh.write(file_data)
                        print(f"已解压: {filename} 到 {extract_path}")
        else:
            messagebox.showerror("错误", "不支持的文件格式")
    except RuntimeError as e:
        error_message = str(e).lower()
        if "bad password" in error_message or "encryption and requires" in error_message:
            new_password = simpledialog.askstring("需要密码", "输入解压密码：", show="*")
            if new_password:
                unzip_file(zip_path, extract_path, new_password)
        else:
            messagebox.showerror("错误", f"解压缩过程中发生错误: {e}")


def get_all_files(file_paths):
    """获取所有文件路径，包括文件夹中的文件"""
    all_files = []
    for path in file_paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    all_files.append(os.path.join(root, file))
        else:
            all_files.append(path)
    return all_files


def update_status(message):
    """更新状态信息显示"""
    status_text.config(state='normal')  # 允许插入
    status_text.delete(1.0, 'end')  # 清空当前内容
    status_text.insert('end', message)  # 插入新内容
    status_text.config(state='disabled')  # 禁止编辑
    root.update_idletasks()


def zip_files(file_paths, output_path, compression_format, encrypt=False, password=None):
    # 获取所有文件，包括文件夹中的所有文件
    all_files = get_all_files(file_paths)
    base_output_path = os.path.dirname(file_paths[0])
    total_files = len(all_files)

    # 确定输出文件路径和名称
    if compression_format == "ZIP":
        output_file = os.path.join(base_output_path, os.path.basename(file_paths[0]) + '.zip') \
            if len(file_paths) == 1 else os.path.join(output_path, os.path.basename(output_path.rstrip('/\\')) + '.zip')

        if encrypt and password:
            zipf = pyzipper.AESZipFile(output_file, 'w', compression=pyzipper.ZIP_DEFLATED)
            zipf.setpassword(password.encode())
            zipf.setencryption(pyzipper.WZ_AES, nbits=128)
        else:
            zipf = pyzipper.ZipFile(output_file, 'w', compression=pyzipper.ZIP_DEFLATED)

        for i, file_path in enumerate(all_files):
            arcname = os.path.relpath(file_path, os.path.dirname(file_paths[0]))
            file_size = os.path.getsize(file_path)
            update_status(f"Compressing {file_path}")
            # 使用 BytesIO 缓存整个文件内容
            with BytesIO() as buffer:
                with open(file_path, 'rb') as f:
                    total_read = 0
                    while chunk := f.read(4096):
                        buffer.write(chunk)
                        total_read += len(chunk)
                        update_block_progress(total_read, file_size)  # 更新块进度条
                buffer.seek(0)  # 重置 BytesIO 位置
                zipf.writestr(arcname, buffer.read())  # 一次性写入整个文件
            update_file_progress(i + 1, total_files)  # 更新文件进度条

        zipf.close()
        print(f"文件已压缩为 ZIP 文件：{output_file}")

    elif compression_format == "7z":
        output_file = os.path.join(base_output_path, os.path.basename(file_paths[0]) + '.7z') \
            if len(file_paths) == 1 else os.path.join(output_path, os.path.basename(output_path.rstrip('/\\')) + '.7z')
        with py7zr.SevenZipFile(output_file, 'w') as archive:
            for i, file_path in enumerate(all_files):
                arcname = os.path.relpath(file_path, os.path.dirname(file_paths[0]))
                update_status(f"Compressing {file_path}")
                archive.write(file_path, arcname=arcname)
                update_file_progress(i + 1, total_files)
        print(f"文件已压缩为 7z 文件：{output_file}")

    elif compression_format == "zstd":
        output_file = os.path.join(base_output_path, os.path.basename(file_paths[0]) + '.zst') \
            if len(file_paths) == 1 else os.path.join(output_path, os.path.basename(output_path.rstrip('/\\')) + '.zst')
        with open(output_file, 'wb') as ofh:
            cctx = zstd.ZstdCompressor()
            with cctx.stream_writer(ofh) as compressor:
                for i, file_path in enumerate(all_files):
                    arcname = os.path.relpath(file_path, os.path.dirname(file_paths[0]))
                    file_size = os.path.getsize(file_path)
                    update_status(f"Compressing {file_path}")
                    # 写入文件头（文件名长度和文件内容长度）
                    compressor.write(struct.pack('<II', len(arcname), file_size))
                    compressor.write(arcname.encode('utf-8'))
                    # 写入文件内容
                    with open(file_path, 'rb') as ifh:
                        while buffer := ifh.read(4096):
                            compressor.write(buffer)
                            update_block_progress(ifh.tell(), file_size)  # 更新块进度条
                    update_file_progress(i + 1, total_files)  # 更新文件进度条
        print(f"文件已压缩为 Zstandard 文件：{output_file}")

    else:
        messagebox.showerror("错误", "不支持的压缩格式")

    update_status("Compression completed")
    delete_temp_file()  # 压缩完成后删除临时文件


def process_files():
    """后台线程，仅负责更新待压缩的文件列表"""
    while True:
        # 读取新的文件路径并更新到临时文件中
        file_paths = read_from_temp_file()
        if file_paths:
            write_to_temp_file(file_paths)  # 保存最新的文件路径
        time.sleep(5)


def select_zip_file():
    """选择压缩文件"""
    file_path = filedialog.askopenfilename(filetypes=[("Compressed files", "*.zip;*.7z;*.rar;*.zst")])
    zip_path.set(file_path)
    update_extract_path()


def select_files_to_compress():
    """选择要压缩的文件"""
    files = filedialog.askopenfilenames()
    file_paths.set(files)
    if files:
        default_output_path = os.path.dirname(files[0])
        output_path.set(default_output_path)
    write_to_temp_file(files)  # 更新临时文件


def select_extract_path():
    """选择解压路径"""
    extract_path.set(filedialog.askdirectory())


def select_output_path():
    """选择输出路径"""
    output_path.set(filedialog.askdirectory())


def update_extract_path(*args):
    """更新解压路径"""
    if auto_unzip.get() and zip_path.get():
        default_extract_path = os.path.splitext(zip_path.get())[0]
        extract_path.set(default_extract_path)


def toggle_password_visibility():
    """切换密码显示"""
    show = "" if show_password.get() else "*"
    password_entry.config(show=show)
    confirm_password_entry.config(show=show)


def start_unzip():
    """开始解压"""
    if not zip_path.get() or not extract_path.get():
        messagebox.showwarning("警告", "请先选择压缩文件和解压路径")
        return
    try:
        unzip_file(zip_path.get(), extract_path.get())
        messagebox.showinfo("完成", "解压缩完成！")
    except Exception as e:
        messagebox.showerror("错误", f"解压缩过程中发生错误: {e}")


def start_compress():
    """通过 GUI 点击开始压缩按钮时触发压缩操作"""
    file_paths = read_from_temp_file()
    if not file_paths:
        messagebox.showwarning("警告", "没有找到待压缩的文件")
        return
    if output_path.get():
        output_dir = output_path.get()
        print("output_dir1", output_dir)
    else:
        output_dir = os.path.dirname(file_paths[0])
        output_dir = output_dir.replace('\\', '/')
        print("output_dir2", output_dir)
    zip_files(file_paths, output_dir, compress_format.get(), encrypt=encrypt_var.get(), password=password.get())
    messagebox.showinfo("完成", "压缩完成！")


if __name__ == "__main__":
    # 初始化 GUI
    if len(sys.argv) >= 3 and sys.argv[1] == "compress":
        selected_files = sys.argv[2:]
        write_to_temp_file(selected_files)

    if is_main_instance():
        root = tk.Tk()
        root.title("压缩和解压工具")
        root.geometry("600x650")
        root.resizable(1, 1)  # 允许窗口大小调整

        zip_path = tk.StringVar()
        extract_path = tk.StringVar()
        file_paths = tk.Variable()
        output_path = tk.StringVar()
        password = tk.StringVar()
        confirm_password = tk.StringVar()
        auto_unzip = tk.BooleanVar(value=True)
        encrypt_var = tk.BooleanVar(value=False)
        show_password = tk.BooleanVar(value=False)
        compress_format = tk.StringVar(value="ZIP")
        status_var = tk.StringVar()

        tk.Label(root, text="选择压缩文件:").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(root, textvariable=zip_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(root, text="选择文件", command=select_zip_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(root, text="选择解压路径:").grid(row=1, column=0, padx=5, pady=5)
        tk.Entry(root, textvariable=extract_path, width=50).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(root, text="选择路径", command=select_extract_path).grid(row=1, column=2, padx=5, pady=5)

        tk.Checkbutton(root, text="智能解压", variable=auto_unzip).grid(row=2, column=1, pady=5)
        tk.Button(root, text="开始解压", command=start_unzip).grid(row=3, column=1, pady=10)

        tk.Label(root, text="选择要压缩的文件:").grid(row=4, column=0, padx=5, pady=5)
        tk.Button(root, text="选择文件", command=select_files_to_compress).grid(row=4, column=2, padx=5, pady=5)

        tk.Label(root, text="选择输出路径:").grid(row=5, column=0, padx=5, pady=5)
        tk.Entry(root, textvariable=output_path, width=50).grid(row=5, column=1, padx=5, pady=5)
        tk.Button(root, text="选择路径", command=select_output_path).grid(row=5, column=2, padx=5, pady=5)

        tk.Label(root, text="选择压缩格式:").grid(row=6, column=0, padx=5, pady=5)
        ttk.Combobox(root, textvariable=compress_format, values=["ZIP", "7z", "zstd"]).grid(row=6, column=1, padx=5,
                                                                                            pady=5)

        tk.Checkbutton(root, text="加密", variable=encrypt_var).grid(row=7, column=1, pady=5)
        tk.Label(root, text="输入密码:").grid(row=8, column=0, padx=5, pady=5)
        password_entry = tk.Entry(root, textvariable=password, show="*", width=50)
        password_entry.grid(row=8, column=1, padx=5, pady=5)

        tk.Label(root, text="确认密码:").grid(row=9, column=0, padx=5, pady=5)
        confirm_password_entry = tk.Entry(root, textvariable=confirm_password, show="*", width=50)
        confirm_password_entry.grid(row=9, column=1, padx=5, pady=5)

        tk.Checkbutton(root, text="显示密码", variable=show_password, command=toggle_password_visibility).grid(row=10,
                                                                                                               column=1,
                                                                                                               pady=5)

        tk.Label(root, text="当前文件压缩进度:").grid(row=11, column=0, padx=5, pady=5)
        block_progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
        block_progress.grid(row=11, column=1, padx=5, pady=5)

        tk.Label(root, text="总文件压缩进度:").grid(row=12, column=0, padx=5, pady=5)
        file_progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
        file_progress.grid(row=12, column=1, padx=5, pady=5)

        # 创建一个可调整大小的 Frame 容器来放置文本框
        frame = tk.Frame(root)
        frame.grid(row=13, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # 添加显示当前操作的文本框，设置为可以调整大小
        status_text = tk.Text(frame, height=5, wrap='word', state='disabled', bg='white')
        status_text.grid(row=0, column=0, sticky="nsew")

        # 使文本框能够随着窗口大小调整
        root.grid_rowconfigure(13, weight=1)
        root.grid_columnconfigure(1, weight=1)

        tk.Button(root, text="开始压缩", command=start_compress).grid(row=14, column=1, pady=10)

        threading.Thread(target=process_files, daemon=True).start()

        root.mainloop()
        release_lock()

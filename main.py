import os

os.environ['UNRAR_LIB_PATH'] = 'unrar/unrar.dll'  # 设置 UNRAR 库路径

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import py7zr
from unrar import rarfile  # 使用 from unrar import rarfile
import pyzipper  # 用于加密的zip压缩


def unzip_file(zip_path, extract_path, pwd=None):
    # 确保提取路径存在
    if not os.path.exists(extract_path):
        os.makedirs(extract_path)

    # 默认解压密码为空
    password = pwd.encode() if pwd else None

    try:
        if zip_path.endswith('.zip'):
            # 处理 ZIP 文件
            with pyzipper.AESZipFile(zip_path, 'r', compression=pyzipper.ZIP_DEFLATED) as zip_ref:
                zip_ref.extractall(extract_path, pwd=password)  # 使用给定密码解压缩
            print(f"ZIP 文件已解压到：{extract_path}")
        elif zip_path.endswith('.7z'):
            # 处理 7z 文件
            with py7zr.SevenZipFile(zip_path, mode='r') as archive:
                archive.extractall(path=extract_path)
            print(f"7z 文件已解压到：{extract_path}")
        elif zip_path.endswith('.rar'):
            # 处理 RAR 文件
            with rarfile.RarFile(zip_path) as rf:
                rf.extractall(path=extract_path)
            print(f"RAR 文件已解压到：{extract_path}")
        else:
            messagebox.showerror("错误", "不支持的文件格式")
    except RuntimeError as e:
        error_message = str(e).lower()
        if "bad password" in error_message or "encryption and requires" in error_message:
            # 弹出密码输入对话框
            new_password = simpledialog.askstring("需要密码", "输入解压密码：", show="*")
            if new_password:
                unzip_file(zip_path, extract_path, new_password)  # 使用新密码重试
        else:
            messagebox.showerror("错误", f"解压缩过程中发生错误: {e}")


def zip_file(folder_path, output_path, compression_format, encrypt=False, password=None):
    if compression_format == "ZIP":
        # 创建 ZIP 文件对象
        if encrypt and password:
            zipf = pyzipper.AESZipFile(output_path + '.zip', 'w', compression=pyzipper.ZIP_DEFLATED)
            # 如果需要加密并且有密码，设置密码
            zipf.setpassword(password.encode())  # 设置密码
            zipf.setencryption(pyzipper.WZ_AES, nbits=128)
            print("password:", password, ",encode:", password.encode())
            # 添加文件到 ZIP
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, arcname=os.path.relpath(file_path, folder_path))
            zipf.close()
        else:
            zipf = pyzipper.ZipFile(output_path + '.zip', 'w', compression=pyzipper.ZIP_DEFLATED)
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, arcname=os.path.relpath(file_path, folder_path))
            zipf.close()
        print(f"文件夹已压缩为 ZIP 文件：{output_path}.zip")

    elif compression_format == "7z":
        with py7zr.SevenZipFile(output_path + '.7z', 'w') as archive:
            archive.writeall(folder_path, os.path.basename(folder_path))
        print(f"文件夹已压缩为 7z 文件：{output_path}.7z")

    else:
        messagebox.showerror("错误", "不支持的压缩格式")


def select_zip_file():
    file_path = filedialog.askopenfilename(filetypes=[("Compressed files", "*.zip;*.7z;*.rar")])
    zip_path.set(file_path)
    update_extract_path()


def select_folder_to_compress():
    folder = filedialog.askdirectory()
    folder_path.set(folder)
    if folder:
        # 自动设置输出路径为被压缩文件夹的同级目录
        default_output_path = os.path.dirname(folder)
        output_path.set(default_output_path)


def select_extract_path():
    extract_path.set(filedialog.askdirectory())


def select_output_path():
    output_path.set(filedialog.askdirectory())


def update_extract_path(*args):
    if auto_unzip.get() and zip_path.get():
        default_extract_path = os.path.splitext(zip_path.get())[0]
        extract_path.set(default_extract_path)


def toggle_password_visibility():
    show = "" if show_password.get() else "*"
    password_entry.config(show=show)
    confirm_password_entry.config(show=show)


def start_unzip():
    if not zip_path.get() or not extract_path.get():
        messagebox.showwarning("警告", "请先选择压缩文件和解压路径")
        return
    try:
        unzip_file(zip_path.get(), extract_path.get())
        messagebox.showinfo("完成", "解压缩完成！")
    except Exception as e:
        messagebox.showerror("错误", f"解压缩过程中发生错误: {e}")


def start_compress():
    if not folder_path.get() or not output_path.get():
        messagebox.showwarning("警告", "请先选择要压缩的文件夹和输出路径")
        return

    if encrypt_var.get():
        if not password.get() or password.get() != confirm_password.get():
            messagebox.showwarning("警告", "请确认密码输入正确")
            return

    try:
        zip_file(folder_path.get(), os.path.join(output_path.get(), os.path.basename(folder_path.get())),
                 compress_format.get(), encrypt=encrypt_var.get(), password=password.get())
        messagebox.showinfo("完成", f"压缩完成！文件已保存为 {compress_format.get()} 格式")
    except Exception as e:
        messagebox.showerror("错误", f"压缩过程中发生错误: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    root.title("压缩和解压工具")

    # 设置窗口启动时的默认尺寸和位置，并禁用大小调整
    root.geometry("600x460")  # 设置窗口宽600，高460
    root.resizable(0, 0)  # 禁用窗口大小调整

    zip_path = tk.StringVar()
    extract_path = tk.StringVar()
    folder_path = tk.StringVar()
    output_path = tk.StringVar()
    password = tk.StringVar()
    confirm_password = tk.StringVar()
    auto_unzip = tk.BooleanVar(value=True)  # 默认选中“智能解压”
    encrypt_var = tk.BooleanVar(value=False)  # 默认不加密
    show_password = tk.BooleanVar(value=False)  # 默认不显示密码
    compress_format = tk.StringVar(value="ZIP")  # 默认压缩格式为 ZIP

    # 绑定变量更新事件
    auto_unzip.trace_add("write", update_extract_path)

    # 解压部分 GUI 组件
    tk.Label(root, text="选择压缩文件:").grid(row=0, column=0, padx=5, pady=5)
    tk.Entry(root, textvariable=zip_path, width=50).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(root, text="选择文件", command=select_zip_file).grid(row=0, column=2, padx=5, pady=5)

    tk.Label(root, text="选择解压路径:").grid(row=1, column=0, padx=5, pady=5)
    tk.Entry(root, textvariable=extract_path, width=50).grid(row=1, column=1, padx=5, pady=5)
    tk.Button(root, text="选择路径", command=select_extract_path).grid(row=1, column=2, padx=5, pady=5)

    tk.Checkbutton(root, text="智能解压", variable=auto_unzip).grid(row=2, column=1, pady=5)
    tk.Button(root, text="开始解压", command=start_unzip).grid(row=3, column=1, pady=10)

    # 压缩部分 GUI 组件
    tk.Label(root, text="选择要压缩的文件夹:").grid(row=4, column=0, padx=5, pady=5)
    tk.Entry(root, textvariable=folder_path, width=50).grid(row=4, column=1, padx=5, pady=5)
    tk.Button(root, text="选择文件夹", command=select_folder_to_compress).grid(row=4, column=2, padx=5, pady=5)

    tk.Label(root, text="选择输出路径:").grid(row=5, column=0, padx=5, pady=5)
    tk.Entry(root, textvariable=output_path, width=50).grid(row=5, column=1, padx=5, pady=5)
    tk.Button(root, text="选择路径", command=select_output_path).grid(row=5, column=2, padx=5, pady=5)

    tk.Label(root, text="选择压缩格式:").grid(row=6, column=0, padx=5, pady=5)
    ttk.Combobox(root, textvariable=compress_format, values=["ZIP", "7z"]).grid(row=6, column=1, padx=5, pady=5)

    # 加密选项
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

    tk.Button(root, text="开始压缩", command=start_compress).grid(row=11, column=1, pady=10)

    root.mainloop()

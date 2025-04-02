import os
import shutil
import winreg
import psutil
import tempfile
import ctypes
import sys
from ctypes import wintypes

class USBKillerRemover:
    def __init__(self):
        # 定义恶意程序特征
        self.malware_names = ['usb.exe', '资料库.exe']
        self.suspicious_dirs = [
            os.path.join(os.environ['APPDATA'], 'usb_killer'),
            'D:\\usb_killer',
            os.path.join(tempfile.gettempdir(), 'usb_killer')
        ]
        self.registry_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        self.registry_value = "USBCopy"

    def kill_malware_processes(self):
        """终止所有关联恶意进程"""
        killed = False
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                if proc.info['name'] in self.malware_names or \
                   any('usb_killer' in proc.info['exe'].lower() for _ in [0]):
                    proc.kill()
                    print(f"[+] 已终止进程: {proc.info['name']}")
                    killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return killed

    def clean_registry(self):
        """清理注册表自启动项"""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                              self.registry_key, 
                              0, winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, self.registry_value)
                print("[+] 已清除注册表自启动项")
                return True
        except WindowsError:
            print("[-] 未发现注册表残留")
            return False

    def remove_malware_files(self):
        """删除所有恶意文件"""
        deleted = False
        for dir_path in self.suspicious_dirs:
            if os.path.exists(dir_path):
                try:
                    shutil.rmtree(dir_path)
                    print(f"[+] 已删除目录: {dir_path}")
                    deleted = True
                except Exception as e:
                    print(f"[-] 删除失败 {dir_path}: {str(e)}")
        return deleted

    def scan_usb_drives(self):
        """扫描并清理U盘残留"""
        infected = False
        for part in psutil.disk_partitions():
            if 'removable' in part.opts.lower():
                drive = part.mountpoint
                for root, _, files in os.walk(drive):
                    for file in files:
                        if file in self.malware_names:
                            try:
                                os.remove(os.path.join(root, file))
                                print(f"[+] 已清理U盘文件: {file}")
                                infected = True
                            except Exception as e:
                                print(f"[-] 清理失败 {file}: {str(e)}")
        return infected

    def run(self):
        """主执行流程"""
        print("=== USB Killer恶意程序清理工具 ===")
        
        # 终止进程
        if self.kill_malware_processes():
            print("[!] 发现并终止了恶意进程")

        # 清理注册表
        self.clean_registry()

        # 删除文件
        if self.remove_malware_files():
            print("[!] 发现并删除了恶意文件")

        # 扫描U盘
        if self.scan_usb_drives():
            print("[!] U盘中发现残留文件")

        print("[√] 清理完成，建议重启计算机")

if __name__ == "__main__":
    if ctypes.windll.shell32.IsUserAnAdmin():
        remover = USBKillerRemover()
        remover.run()
    else:
        print("请以管理员权限运行此程序！")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
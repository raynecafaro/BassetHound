# Rayne Cafaro & Jonathan Jang
from subprocess import Popen, PIPE, STDOUT
import argparse, os, sys

class BassetHound(object):
    def __init__(self, lkm) -> None:
        if os.getuid():
            print("basset_hound.py must be run with UID 0 [root or sudo].")
            sys.exit(1)

        if lkm is None:
            self.lkm = "./basset_hound_module.ko"
        else:
            self.lkm = lkm

        self.compare()
        
    def parse_ps(self) -> tuple:
        cmd = "ps -ef | awk \'{print $2}\'"
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        output = p.stdout.readlines()[1:]
        process_id_list = list()
        for line in output:
            process_id_list.append(int(line.decode()))
       
        process_id_list_count = len(process_id_list)
        
        return (process_id_list, process_id_list_count)

    def parse_ko_out(self) -> tuple:
        lines = list()
        
        cmd = "rmmod basset_hound_module.ko"
        Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        
        cmd = "dmesg --clear"
        Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

        cmd = "insmod basset_hound_module.ko"
        Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)

        cmd = 'dmesg'
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        output = p.stdout.readlines()
        
        for line in output:
            if "==" in line.decode():
                lines.append(line.decode())
        if len(lines) == 0:
            print("The kernel module does not appear to have loaded.")
            sys.exit(1)


        task_list = lines[:-1]
        task_list_count = int(lines[-1].split()[-1].strip('[]'))

        if len(task_list) != task_list_count:
            print("ALERT: The dmesg task list count does not match exported task list.")
   
        return (task_list, task_list_count)

    def compare(self):
        process_id_list, process_id_list_count = self.parse_ps()
        task_list, task_list_count = self.parse_ko_out()

        if process_id_list_count != task_list_count:
            for task in task_list:
                stripped_task = int(task.split()[-1].strip('[]'))
                if stripped_task not in process_id_list:
                    if "insmod" in task:
                        process_id_list_count = process_id_list_count - 1
                        print("Probably not a hidden process: " + task)
                        continue

                    if "systemd-udev" in task:
                        process_id_list_count = process_id_list_count - 1
                        print("Probably not a hidden process: " + task)
                        continue

                    if "kworker/" in task:
                        process_id_list_count = process_id_list_count - 1
                        print("Probably not a hidden process: " + task)
                        continue
                    
                    print("Hidden process: " + task)
                    
            
            if process_id_list_count != task_list_count:
                print("ALERT: Hidden process indicates a potential rootkit.\n")
            else:
                print("No hidden processes detected.\n")

            print("Kernel Task List Count: " + str(task_list_count))
            print("Userland Process List Count: " + str(process_id_list_count))
            print()

        else:
            print("No hidden processes detected.")

def main():
    parser = argparse.ArgumentParser(description='Detect processes hidden by a rootkit.')
    parser.add_argument('--lkm', type=str, help='Location of basset_hound_module.ko', default=None)
    args = parser.parse_args()

    hound = BassetHound(args.lkm)

if __name__ == "__main__":
    main()

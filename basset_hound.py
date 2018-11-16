# Rayne Cafaro & Jonathan Jang
from subprocess import Popen, PIPE, STDOUT
import argparse

class BassetHound(object):
    def __init__(self, lkm:str, kmsg:str) -> None:
        if lkm is None:
            self.lkm = "./basset_hound_module.ko"
        else:
            self.lkm = lkm
        
        if kmsg is None:
            pass    
        else:
            self.kmsg = kmsg

    def parse_ps(self) -> tuple:
        process_list = None
        process_list_count = None
        return (process_list, process_list_count)

    def parse_ko_out(self) -> tuple:
        lines = list()
        
        cmd = 'dmesg'
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        output = p.stdout.readlines()
        
        for line in output:
            if "==" in line.decode():
                lines.append(line.decode())

        task_list = lines[:-1]
        task_list_count = int(lines[-1].split()[-1].strip('[').strip(']'))

        if len(task_list) is not task_list_count:
            print("Potential rootkit detected")
   
        return (task_list, task_list_count)
        
    def compare(self):
        process_list = self.parse_ps()
        kernel_task_list = self.parse_ko_out()

        print(kernel_task_list[0], kernel_task_list[1])

def main():
    parser = argparse.ArgumentParser(description='Detect processes hidden by a rootkit.')
    parser.add_argument('--lkm', type=str, help='Location of basset_hound_module.ko', default=None)
    parser.add_argument('--kmsg', type=str, help='Location of kmsg file', default=None)

    args = parser.parse_args()

    HoundObj = BassetHound(args.lkm, args.kmsg)
    HoundObj.compare()

if __name__ == "__main__":
    main()

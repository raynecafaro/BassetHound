# Rayne Cafaro & Jonathan Jang
from subprocess import Popen, PIPE, STDOUT
import argparse, os

class BassetHound(object):
    def __init__(self, lkm:str) -> None:
        if lkm is None:
            self.lkm = "./basset_hound_module.ko"
        else:
            self.lkm = lkm
        
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
        
        # TODO: try block for priv level
        os.system("dmesg --clear")
        cmd = 'dmesg'
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
        output = p.stdout.readlines()
        
        # TODO: Throw Kernel Module not loaded error if no "==" present
        for line in output:
            if "==" in line.decode():
                lines.append(line.decode())

        task_list = lines[:-1]
        task_list_count = int(lines[-1].split()[-1].strip('[').strip(']'))

        if len(task_list) is not task_list_count:
            print("ALERT: The dmesg task list count does not match exported task list.")
   
        return (task_list, task_list_count)
        
    def compare(self):
        process_id_list, process_id_list_count = self.parse_ps()
        task_list, task_list_count = self.parse_ko_out()

        if process_id_list_count is not task_list_count:
            print("ALERT: The process list count does not match the task list count.\n")
            for task in task_list:
                print(task)

        else:
            print("No hidden processes detected.")


def main():
    parser = argparse.ArgumentParser(description='Detect processes hidden by a rootkit.')
    parser.add_argument('--lkm', type=str, help='Location of basset_hound_module.ko', default=None)

    args = parser.parse_args()

    HoundObj = BassetHound(args.lkm)
    HoundObj.compare()

if __name__ == "__main__":
    main()

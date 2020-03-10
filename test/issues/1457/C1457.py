#
# Test script for issue #1439
#

import os
import sys
import subprocess

def get_command_result(cmd):
    results = subprocess.Popen(
        cmd, stdout=subprocess.PIPE,
        shell=True).stdout.readlines()
    return [str(x).rstrip("\n") for x in results]

def enumerate_cpu(cpu_list):
    allcpus = []
    for ranged_cpu in cpu_list.split(','):
        try:
            cpu_begin, cpu_end = ranged_cpu.split('-')
        except ValueError:
            cpu_begin = cpu_end = ranged_cpu
        for i in range(int(cpu_begin), int(cpu_end) + 1):
            allcpus.append(i)
    allcpus.sort()
    return allcpus

def get_online_cpu():
    online_file = open('/sys/devices/system/cpu/online', 'r')
    return online_file.readlines()[0].strip()

def get_cpuinfo_processors():
    processors = []
    cpuinfo_file = open('/proc/cpuinfo', 'r')
    for line in cpuinfo_file.readlines():
        if line.startswith('processor'):
            processor = int(line.strip().split()[-1])
            processors.append(processor)
    return processors

def main():
    onlines = enumerate_cpu(get_online_cpu())
    processors = get_cpuinfo_processors()

    print '# of online cpus:', len(onlines)
    print '# of cpuinfo processors:', len(processors)
    if len(onlines) != len(processors):
        print 'ERROR: # of processors is not equal to # of cpus'
        print 'FAIL'
        exit()

    i = 0
    for cpu in processors:
        print i, 'processor:', cpu
        if i != cpu:
            print 'ERROR: processor number is not ordered'
            print 'FAIL'
            exit()
        i = i + 1

    print 'SUCCESS'

if __name__ == '__main__':
    main()

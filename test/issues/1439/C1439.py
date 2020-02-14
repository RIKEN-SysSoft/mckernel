#
# Test script for issue #1439
#

import os
import sys
import subprocess

mckdir = os.getenv('MCK_DIR')
mckbin = mckdir + '/bin'
mcksbin = mckdir + '/sbin'
mcreboot = mcksbin + '/mcreboot.sh'
mcstop = mcksbin + '/mcstop+release.sh'
mcexec = mckbin + '/mcexec'


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

def bind_cpu_core(catcmd, allcpus):
    cpucores = {}
    for cpu in allcpus:
        sysfile = '/sys/devices/system/cpu/cpu%d/topology/core_id' % cpu
        core_id = get_command_result(catcmd + ' ' + sysfile)[0]
        cpucores[cpu] = int(core_id)
    return cpucores

def compare_cores(linuxcpucores, mckernelcpucores):
    linuxcpus = linuxcpucores.keys()
    linuxcpus.sort()
    linuxcores = []
    for linuxcpu in linuxcpus:
        linuxcores.append(linuxcpucores[linuxcpu])
    mckernelcpus = mckernelcpucores.keys()
    mckernelcpus.sort()
    mckernelcores = []
    for mckernelcpu in mckernelcpus:
        mckernelcores.append(mckernelcpucores[mckernelcpu])
    coremap = {}
    seq = 0
    for i in range(len(linuxcores)):
        linuxcore = linuxcores[i]
        mckernelcore = mckernelcores[i]
        if linuxcore in coremap:
            if mckernelcore != coremap[linuxcore]:
                print 'FAIL'
                quit()
        else:
            if seq != mckernelcore:
                print 'FAIL'
                quit()
            seq = seq + 1
            coremap[linuxcore] = mckernelcore

def main():
    argvs = sys.argv
    argc = len(argvs)
    if (argc != 2):
        print 'Usage: python %s <cpu_list>' % argvs[0]
        quit()
    print 'cpu_list = %s' % argvs[1]
    cpulist = argvs[1]
    linuxcpus = enumerate_cpu(cpulist)
    linuxcpucores = bind_cpu_core('cat', linuxcpus)
    print 'linux: '
    print linuxcpucores
    get_command_result('sudo ' + mcreboot + ' -c ' + cpulist)
    mckernelcpus = [i for i in range(0, len(linuxcpus))]
    mckernelcpucores = bind_cpu_core(mcexec + ' cat', mckernelcpus)
    print 'mckernel: '
    print mckernelcpucores
    get_command_result('sudo ' + mcstop)
    compare_cores(linuxcpucores, mckernelcpucores)
    print 'SUCCESS'

if __name__ == '__main__':
    main()

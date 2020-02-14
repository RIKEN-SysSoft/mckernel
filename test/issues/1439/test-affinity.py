import os
import sys
import subprocess
import math

def get_command_result(cmd):
    print cmd
    results = subprocess.Popen(
        cmd, stdout=subprocess.PIPE,
        shell=True).stdout.readlines()
    return [str(x).rstrip("\n") for x in results]

def get_cpus():
    cpus = []
    online_file = open('/sys/devices/system/cpu/online', 'r')
    for cpurange in online_file.readlines()[0].strip().split(','):
        try:
            cpurange_start, cpurange_end = cpurange.split('-')
        except ValueError:
            cpurange_start = cpurange_end = cpurange
        for cpu in range(int(cpurange_start), int(cpurange_end) + 1):
            cpus.append(cpu)
    return cpus

def get_omp_places_cores(cpus):
    places = []
    map_cpu_to_place = {}
    for cpu in cpus:
        if cpu not in map_cpu_to_place:
            siblings_file = open('/sys/devices/system/cpu/cpu{0}/topology/thread_siblings_list'.format(cpu))
            place = []
            siblings = siblings_file.readlines()[0].strip().split(',')
            for sibling in siblings:
                place.append(int(sibling))
            places.append(place)
            for sibling in siblings:
                map_cpu_to_place[int(sibling)] = place
    return places, map_cpu_to_place

def index_of_place(places, cpu):
    i = 0
    for place in places:
        if cpu in place:
            return i
        i = i + 1
    return -1

def index_of_subpartition(subpartition, place):
    i = 0
    for placelist in subpartition:
        if place in placelist:
            return i
        i = i + 1
    return -1

def get_estimated_bind(omp_proc_bind, nthreads, places):
    if omp_proc_bind == 'close':
        return get_estimated_bind_close(0, 0, nthreads, places)
    elif omp_proc_bind == 'spread':
        return get_estimated_bind_spread(0, 0, nthreads, places)
    return None

def get_estimated_bind_close(master_thread, master_cpu, nthreads, places):
    map_thread_to_place = {}
    nplaces = len(places)
#    print 'nthreads =', nthreads
#    print 'nplaces =', nplaces
    if nthreads <= nplaces:
        place_idx = index_of_place(places, master_cpu)
#        print 'place_idx =', place_idx
        for i in range(nthreads):
            thread = (master_thread + i) % nthreads
            map_thread_to_place[thread] = places[(place_idx + i) % nplaces]
    else:
        s = [0] * nplaces
        for p in range(nplaces):
            if nplaces - p <= nthreads % nplaces: # implementation defined
                s[p] = nthreads / nplaces + 1 # ceil
            else:
                s[p] = nthreads / nplaces # floor
#            print 's[', p, '] =', s[p]
        i_begin = 0
        place_idx = index_of_place(places, master_cpu)
        for p in range(nplaces):
            for i in range(i_begin, i_begin + s[p]):
                thread = (master_thread + i) % nthreads
                map_thread_to_place[thread] = places[(place_idx + p) % nplaces]
            i_begin = i_begin + s[p]
    return map_thread_to_place

def get_estimated_bind_spread(master_thread, master_cpu, nthreads, places):
    map_thread_to_place = {}
    nplaces = len(places)
    if nthreads <= nplaces:
        places_subpartition = []
        p_begin = 0
        for i in range(nthreads):
            if nthreads - i <= nplaces % nthreads: # implementation defined
                size_places_subpartition = nplaces / nthreads + 1 # ceil
            else:
                size_places_subpartition = nplaces / nthreads # floor
            places_subpartition.append(places[p_begin:p_begin + size_places_subpartition])
            p_begin = p_begin + size_places_subpartition
        place_idx = index_of_place(places, master_cpu)
        places_subpartition_idx = index_of_subpartition(places_subpartition, places[place_idx])
        for i in range(nthreads):
            thread = (master_thread + i) % nthreads
            if thread == master_thread:
                map_thread_to_place[thread] = places[place_idx]
            else:
                map_thread_to_place[thread] = places_subpartition[(places_subpartition_idx + i) % nthreads][0]
    else:
        threads = []
        for i in range(nthreads):
            threads.append(i)
        threads_subpartition = []
        i_begin = 0
        for p in range(nplaces):
            if nplaces - p <= nthreads % nplaces: # implementation defined
                size_threads_subpartition = nthreads / nplaces + 1 # ceil
            else:
                size_threads_subpartition = nthreads / nplaces # floor
            threads_subpartition.append(threads[i_begin:i_begin + size_threads_subpartition])
            i_begin = i_begin + size_threads_subpartition
        place_idx = index_of_place(places, master_cpu)
        for p in range(nplaces):
            for i in threads_subpartition[p]:
                thread = (master_thread + i) % nthreads
                map_thread_to_place[thread] = places[p]
    return map_thread_to_place

def run_and_get_omp_cpu_affinity(omp_proc_bind, nthreads):
    os.environ['NODES'] = '1'
    os.environ['PPN'] = '1'
    os.environ['HWLOC_HIDE_ERRORS'] = '1'
    os.environ['OMP_PLACES'] = 'cores'
    os.environ['OMP_PROC_BIND'] = omp_proc_bind
    os.environ['OMP_NUM_THREADS'] = str(nthreads)
    command = './show-omp-cpu-affinity'
    result_map_thread_to_cpu = {}
    for line in get_command_result(command):
        outputs = line.split(' ')
        thread = outputs[1]
        cpu = outputs[3]
        result_map_thread_to_cpu[int(thread)] = int(cpu)
    return result_map_thread_to_cpu

def compare_result(nthreads, map_thread_to_place, result_map_thread_to_cpu):
    try:
        for thread in range(nthreads):
            place = map_thread_to_place[thread]
            if result_map_thread_to_cpu[thread] not in place:
                return False
        return True
    except KeyError:
        return False

def test_cpu_affinity(cpus, omp_proc_bind, nthreads, places):
    map_thread_to_place = get_estimated_bind(omp_proc_bind, nthreads, places)
    result_map_thread_to_cpu = run_and_get_omp_cpu_affinity(omp_proc_bind, nthreads)
    if compare_result(nthreads, map_thread_to_place, result_map_thread_to_cpu):
        result = 'SUCCESS'
    else:
        result = 'FAIL'
    print "MAP_THREAD_TO_PLACE({0}): {1}".format(omp_proc_bind, map_thread_to_place)
    print "RESULT_MAP_THREAD_TO_CPU: {0}".format(result_map_thread_to_cpu)
    print "#CPU: {}, #PLACE: {}, OMP_PLACES: cores, OMP_PROC_BIND: {}, OMP_NUM_THREAD: {}, RESULT: {}".format(len(cpus), len(places), omp_proc_bind, nthreads, result)

def main():
    cpus = get_cpus()
    print 'CPUS:', cpus
    places, map_cpu_to_place = get_omp_places_cores(cpus)
    print 'PLACES:', places
    print 'MAP_CPU_TO_PLACE', map_cpu_to_place
    print

    nplaces = len(places)
    for nthreads in range(2, nplaces * 4 + 1):
        if nthreads < nplaces and nplaces % nthreads > 0:
            continue
        if nthreads >= nplaces and nthreads % nplaces > 0:
            continue
        test_cpu_affinity(cpus, 'close', nthreads, places)
        print
        test_cpu_affinity(cpus, 'spread', nthreads, places)
        print

if __name__ == '__main__':
    main()


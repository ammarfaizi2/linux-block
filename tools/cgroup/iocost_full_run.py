#!/bin/env python3

import argparse
import os
import sys
import glob
import subprocess
import time
import threading
import json
import random
import tempfile
import glob

test_slice = 'test.slice'
high_unit = 'ioc-high.scope'
low_unit = 'ioc-low.scope'
high_cgrp = f'/sys/fs/cgroup/{test_slice}/{high_unit}'
low_cgrp = f'/sys/fs/cgroup/{test_slice}/{low_unit}'
high_testfile = 'ioc-testfile-high'
low_testfile = 'ioc-testfile-low'
shutting_down = False

parser = argparse.ArgumentParser()
parser.add_argument('--base-weight', type=int, default=1000)
parser.add_argument('--high-weight', type=int, default=500)
parser.add_argument('--low-weight', type=int, default=100)
parser.add_argument('--high-mem', type=float, metavar='GIGABYTES', default=1)
parser.add_argument('--low-mem', type=float, metavar='GIGABYTES', default=1)
parser.add_argument('--rand-depth', type=int, default=64)
parser.add_argument('--blocksize', type=int, default=32768)
parser.add_argument('--duration', type=int, default=60)
parser.add_argument('--numjobs', type=int, default=1)
parser.add_argument('--no-iocost', action='store_true')
parser.add_argument('--exp-pair', default = None)
parser.add_argument('--rand', choices=['direct-aio', 'direct-sync', 'buffered-sync'],
                    default='direct-aio')
parser.add_argument('--disable-cow', action='store_true')
parser.add_argument('--compress-pct', type=int, default=0)
parser.add_argument('--testfile-size', type=float, metavar='GIGABYTES', default=16)
parser.add_argument('--mioc-path', default=f'{sys.path[0]}/iocost_monitor.py')
parser.add_argument('--tempdir', default='/dev/shm')
parser.add_argument('--scribe-out-file', default=None)

args = parser.parse_args()
high_weight = args.high_weight
low_weight = args.low_weight
high_mem = int(args.high_mem * 2 ** 30)
low_mem = int(args.high_mem * 2 ** 30)
testfile_size = int(args.testfile_size * 2 ** 30)
numjobs = args.numjobs
offset_inc = int(testfile_size / numjobs)

exp_id = random.randint(1, 10000001)

fio_base_args  = \
    f'--blocksize={args.blocksize} --replay_align=4096 ' \
    f'--time_based --log_avg_msec=100 --log_unix_epoch=1 --group_reporting'

if args.compress_pct > 0:
    fio_base_args += f' --buffer_compress_percentage={args.compress_pct} '

fio_seqr_args  = f'--readwrite=read --ioengine=sync'
fio_seqw_args  = f'--readwrite=write --ioengine=sync'

if args.numjobs > 1:
    fio_seqr_args += f' --numjobs={numjobs} --offset_increment={offset_inc}'
    fio_seqw_args += f' --numjobs={numjobs} --offset_increment={offset_inc}'

if args.rand == 'direct-aio':
    fio_rand_base = \
        f'--iodepth={args.rand_depth} --direct=1 --ioengine=libaio ' \
        f' --numjobs={numjobs}'
elif args.rand == 'direct-sync':
    fio_rand_base = f'--numjobs={args.rand_depth * numjobs} --direct=1 --ioengine=sync'
else:
    fio_rand_base = f'--numjobs={args.rand_depth * numjobs} --ioengine=sync'

fio_randr_args = f'{fio_rand_base} --readwrite=randread --randrepeat=0'
fio_randw_args = f'{fio_rand_base} --readwrite=randwrite --randrepeat=0'

class FioArgs:
    def __init__(self, id, fio_args):
        self.id = id
        if fio_args is None:
            self.args = None
        else:
            self.args = f'{fio_base_args} {fio_args}'

    def __repr__(self):
        return f'{self.id}: {self.args}'

fio_none  = FioArgs('none' , None)
fio_randr = FioArgs('randr', fio_randr_args)
fio_seqr  = FioArgs('seqr' , fio_seqr_args)
fio_randw = FioArgs('randw', fio_randw_args)
fio_seqw  = FioArgs('seqw' , fio_seqw_args)

exp_seq = (
    ( fio_randr, ( fio_none, fio_randr, fio_seqr, fio_randw, fio_seqw )),
    ( fio_seqr,  ( fio_none, fio_randr, fio_seqr, fio_randw, fio_seqw )),
    ( fio_randw, ( fio_none, fio_randr, fio_seqr, fio_randw, fio_seqw )),
    ( fio_seqw,  ( fio_none, fio_randr, fio_seqr, fio_randw, fio_seqw )),
)

fio_args = {
    'none' : fio_none,
    'randr': fio_randr,
    'seqr' : fio_seqr,
    'randw': fio_randw,
    'seqw' : fio_seqw,
}

if args.exp_pair:
    high_name, low_name = args.exp_pair.split(',')
    exp_seq = (( fio_args[high_name], ( fio_args[low_name], )), )

# determine ('DEVNAME', 'MAJ:MIN') for @path
def dir_to_dev(path):
    # find the block device the current directory is on
    devname = subprocess.run(['findmnt', '-nvo', 'SOURCE', '-T', path],
                             stdout=subprocess.PIPE).stdout
    devname = os.path.basename(devname).decode('utf-8').strip()

    # partition -> whole device
    parents = glob.glob('/sys/block/*/' + devname)
    if len(parents):
        devname = os.path.basename(os.path.dirname(parents[0]))
    rdev = os.stat('/dev/' + devname).st_rdev
    return (devname, f'{os.major(rdev)}:{os.minor(rdev)}')

def create_testfile(path, size):
    if os.path.isfile(path) and os.stat(path).st_size == size:
        return

    print(f'Creating testfile {path}')
    subprocess.check_call(f'rm -f {path}', shell=True)
    subprocess.check_call(f'touch {path}', shell=True)
    if args.disable_cow:
        subprocess.check_call(f'/usr/bin/chattr +C {path}', shell=True)
    if args.compress_pct > 0:
        subprocess.check_call(f'fio --name=prep --size=4096 --fallocate=none '
                              f'--filename={path} --filesize={size} '
                              f'--buffer_compress_percentage={args.compress_pct}',
                              shell=True)
    else:
        subprocess.check_call(f'pv -s {size} -pr /dev/urandom | '
                              f'dd of={path} count={size} '
                              f'iflag=count_bytes,fullblock oflag=direct bs=16M status=none',
                              shell=True)

def scribe_out(time, workload, kv_dict):
    global exp_id, scribe_out_file

    res = {
        'int': {
            'time': round(float(time)),
        },
        'normal': {
            'experiment': f'{exp_id}',
            'workload': workload,
        }
    }

    for k, v in kv_dict.items():
        res['int'][k] = round(float(v))

    scribe_out_file.write(json.dumps(res) + '\n')
    scribe_out_file.flush()

def mioc_pipe_fn(pipe):
    while True:
        line = pipe.readline()
        if not line:
            break
        j = json.loads(line)

        if 'device' in j:
            scribe_out(j['timestamp'], 'kernel', { 'vrate_pct': j['vrate_pct'] })
        elif 'cgroup' in j:
            cgrp = os.path.basename(j['cgroup'])
            if cgrp in (high_unit, low_unit):
                kv_dict = {}
                for k in ('weight_inuse', 'hweight_active_pct', 'hweight_inuse_pct', 'usage_pct'):
                    kv_dict[k] = round(j[k])
                scribe_out(j['timestamp'], cgrp, kv_dict)

def stat_pipe_fn(pipe, out_ar):
    out_ar[0] = 'starting'
    cnt = 0
    while True:
        try:
            line = pipe.readline()
            if not len(line):
                out_ar[0] = 'exiting'
                return
        except Exception as e:
            out_ar[0] = f'Exception: {e}'
            return

        line = line.decode('utf-8').split('\r')
        line.reverse()
        for l in line:
            l = l.strip()
            if len(l):
                break
        out_ar[0] = f'[{cnt:3}] {l}'
        cnt += 1

def cgroup_io_stat_read(path, devno):
    try:
        with open(path + '/io.stat', 'r') as f:
            for line in f:
                tokens = line.split()
                if tokens[0] != devno:
                    continue
                bytes = 0
                ios = 0
                for tok in tokens[1:]:
                    k, v = tok.split('=')
                    if k[1:] == 'bytes':
                        bytes += int(v)
                    elif k[1:] == 'ios':
                        ios += int(v)
                return bytes, ios
    except:
        pass
    return None, None

def cgroup_io_stat_fn(devno):
    global high_cgrp, low_cgrp, shutting_down

    hb, hi = cgroup_io_stat_read(high_cgrp, devno)
    lb, li = cgroup_io_stat_read(low_cgrp, devno)

    while not shutting_down:
        time.sleep(1)
        now = time.time()

        new_hb, new_hi = cgroup_io_stat_read(high_cgrp, devno)
        kv_dict = {}
        if hb is not None and new_hb is not None and \
           new_hb > hb and new_hi > hi:
            kv_dict['dev_kbps'] = (new_hb - hb) / 1024
            kv_dict['dev_iops'] = new_hi - hi
            scribe_out(now, high_unit, kv_dict)
        hb = new_hb
        hi = new_hi

        new_lb, new_li = cgroup_io_stat_read(low_cgrp, devno)
        kv_dict = {}
        if lb is not None and new_lb is not None and \
           new_lb > lb and new_li > li:
            kv_dict['dev_kbps'] = (new_lb - lb) / 1024
            kv_dict['dev_iops'] = new_li - li
            scribe_out(now, low_unit, kv_dict)
        lb = new_lb
        li = new_li

def start_fio_run(unit, io_weight, memory_high, fio_args, runtime, filename,
                  stat_ar, tempdir):
    if fio_args.args is None:
        cmd = f'echo sleeping for {runtime} secs...; sleep {runtime}'
    else:
        cmd = f'systemd-run --scope --same-dir --slice={test_slice} --unit={unit} ' \
              f'-p "IOWeight={io_weight}" -p "MemoryHigh={memory_high}" '           \
              f'fio --name {fio_args.id} {fio_args.args} --runtime={runtime} '      \
              f'--filename={filename} --eta=always --eta-newline=1 '                \
              f'--write_iops_log={tempdir}/fio --write_bw_log={tempdir}/fio '       \
              f'--write_lat_log={tempdir}/fio '
        print(f'\nRunning f{unit} with parameter set f{fio_args.id}')
        print(f'  cmd="{cmd}"')
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    threading.Thread(target=stat_pipe_fn, args=(p.stdout, stat_ar)).start()
    return p

def process_fio_logs(dir, workload):
    out = ''
    for log, key in (('lat', 'latency'),
                     ('slat', 'submission_latency'),
                     ('clat', 'completion_latency'),
                     ('iops', 'iops'),
                     ('bw', 'bandwidth')):
        fname = f'{dir}/fio_{log}.1.log'
        if not os.path.isfile(fname):
            continue

        f = open(fname, 'r')
        for line in f:
            items = line.split(',')
            scribe_out(float(items[0]) / 1000, workload, { key: items[1] })

# execution starts here
subprocess.call(f'systemctl stop {high_unit} {low_unit}', shell=True)
subprocess.call(f'systemctl reset-failed', shell=True)

devname, devno = dir_to_dev('.')
print(f'Testing on {devname}({devno}) mioc at {args.mioc_path}')

create_testfile(high_testfile, testfile_size)
create_testfile(low_testfile, testfile_size)
subprocess.check_call(f'echo 1 > /proc/sys/vm/drop_caches', shell=True)

# basic cgroup configs
for p in glob.glob('/sys/fs/cgroup/**/io.latency', recursive=True):
    with open(p, 'w') as f:
        f.write(f'{devno} target=0')

with open('/sys/fs/cgroup/io.cost.qos', 'w') as f:
    f.write(f'{devno} enable={0 if args.no_iocost else 1}')

subprocess.check_call(f'systemctl set-property {test_slice} IOWeight={args.base_weight} '
                      f'MemoryHigh={high_mem + low_mem}', shell=True)

# create scribe output file
scribe_tmpdir = tempfile.TemporaryDirectory(prefix='fullrun-scribe-', dir=args.tempdir)

if args.scribe_out_file:
    scribe_out_path = args.scribe_out_file
else:
    scribe_out_path = f'{scribe_tmpdir.name}/scribe.out'

scribe_out_file = open(scribe_out_path, 'w')

# start iocost_monitor.py and scuba reporting
mioc = subprocess.Popen(f'{args.mioc_path} --json {devname}', shell=True, stdout=subprocess.PIPE)

print('Waiting for mioc to startup...', end='', flush=True)
mioc.stdout.readline()
print(' done')

mioc_pipe = threading.Thread(target=mioc_pipe_fn, args=(mioc.stdout,))
mioc_pipe.start()

cgroup_io_stat = threading.Thread(target=cgroup_io_stat_fn, args=(devno,))
cgroup_io_stat.start()

# we're ready for actual testing
started_at = time.time()

for high_exp, low_exps in exp_seq:
    cursor_at = time.time()
    high_stat = ['']
    high_tempdir = tempfile.TemporaryDirectory(prefix='fullrun-high-', dir=args.tempdir)
    high_p = start_fio_run(high_unit, high_weight, high_mem, high_exp,
                           len(low_exps) * args.duration, high_testfile,
                           high_stat, high_tempdir.name)
    for low_exp in low_exps:
        cursor_at += args.duration
        low_stat = ['']
        low_tempdir = tempfile.TemporaryDirectory(prefix='fullrun-low-', dir=args.tempdir)
        low_p = start_fio_run(low_unit, low_weight, low_mem, low_exp,
                              max(round(cursor_at - time.time()), 0), low_testfile,
                              low_stat, low_tempdir.name)
        while True:
            done = False
            try:
                low_p.wait(1)
                done = True
            except subprocess.TimeoutExpired:
                pass
            if done:
                break
            print('')
            print(f'HIGH {high_exp.id:5}: {high_stat[0]}')
            print(f'LOW  {low_exp.id:5}: {low_stat[0]}')

        process_fio_logs(low_tempdir.name, low_unit)

    high_p.wait()
    process_fio_logs(high_tempdir.name, high_unit)

shutting_down = True

mioc.kill()
mioc_pipe.join()
cgroup_io_stat.join()

subprocess.check_call(f'scribe_cat perfpipe_newella_io < {scribe_out_path}', shell=True)
print(f'Open https://fburl.com/scuba/su6i9u9y and use start time {int(started_at)} and end time {int(time.time())}')

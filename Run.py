#!/usr/bin/python3.6

import os
from datetime import datetime, timedelta
from time import sleep
import Flowmon_REST


tmp_path = 'tmp/'

# return last flowmon spawn time
def round_time(time):
    t_min = time.minute % 5
    t_sec = time.second
    t_mic = time.microsecond
    time = time - timedelta(minutes=t_min, seconds=t_sec, microseconds=t_mic)
    return time


# download flows from flowmon by rest
def get_flows(time, pw):
    date_path = time.strftime('%Y/%m/%d/')
    file_path = 'nfcapd.' + time.strftime('%Y%m%d%H%M')
    return Flowmon_REST.download(date_path=date_path, file_path=file_path, password=pw)


# cleaning tmp dir after every loop (5min) without last records
def clean_tmp_directory(time):
    actual_time = time.strftime('%Y%m%d%H%M')
    esc_tmp_path = tmp_path.replace('/', '\/')

    # remove all files from tmp without last loop
    remove_old_files = f"ls -1 {tmp_path} " \
                       f"| grep -Ev '^{actual_time}_[a-z]{{3,4}}\\.csv$' " \
                       f"| grep -E '^([0-9]{{12}}_[a-z]{{3,4}}\\.csv)|([0-9]{{12}}\.csv~?)$' " \
                       f"| sed  -e 's/^/{esc_tmp_path}/' " \
                       f"| xargs rm "
    print(f'Cleaning ... {remove_old_files}')
    os.system(remove_old_files)


# main loop
def run(pw):
    time = round_time(now)
    if not os.path.isdir(tmp_path):
        os.mkdir(tmp_path, 0o755);
    while True:
        print(f'Actual time: \t{time}')
        file_path = get_flows(time, pw)
        make_sessions_every_5_min(file_path, time)
        clean_tmp_directory(time)
        sleep(300 - (time.total_seconds() % 300))
        time = time + timedelta(minutes=5)


if __name__ == '__main__':
    print(f'Argument List: \t{str(sys.argv)}')
    if '-p' in sys.argv:
        print('Enter your private key password:')
        pw = getpass.getpass()
    else:
        pw = login.pw
    run(pw)

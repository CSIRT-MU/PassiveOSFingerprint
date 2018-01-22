#!/usr/bin/python3

import time
from neo4jDB import *
from getpass import getpass
from configparser import ConfigParser
from json import JSONDecodeError, dumps, load
from datetime import datetime, timedelta
from Flowmon_REST import download
from OS_parser import make_sessions


def round_time(time):
    """
    Get time of last flowmon export.
    :param time: current time.
    :return: rounded time.
    """
    t_min = time.minute % 5
    t_sec = time.second
    t_mic = time.microsecond
    time = time - timedelta(minutes=t_min, seconds=t_sec, microseconds=t_mic)
    return time


def get_prev_sessions(sessions_path):
    """
    Parse json file to sessions
    :param sessions_path: path to json file
    :return: dictionary of sessions in format dict[ip] = os
    """
    result = {}
    with open(sessions_path, 'r') as prev_sessions:
        try:
            sessions = load(prev_sessions)
            for record in sessions['skip']:
                result[record['ip']] = record['os']
            for record in sessions['add']:
                result[record['ip']] = record['os']
            for record in sessions['upt']:
                result[record['ip']] = record['os']
            return result
        except (ValueError, JSONDecodeError) as e:
            print(e)
            return {}


def write_session(prev_sessions, sessions, time, session_path):
    """
    Rewrite json file with new data
    :param prev_sessions: old sessions
    :param sessions: new sessions
    :param time: timestamp of processed flows
    :param session_path: path to json file
    :return: None
    """
    with open(session_path, 'w') as session_file:
        # create json struct
        data = {}
        data['time'] = str(time)
        data['del'] = []
        data['upt'] = []
        data['add'] = []
        data['skip'] = []

        for key, val in sessions.items():
            if key not in prev_sessions:
                data['add'].append({"ip": key, "os": val})
                continue
            if val == prev_sessions[key]:
                data['skip'].append({"ip": key, "os": val})
            else:
                data['upt'].append({"ip": key, "os": val})
        for key, val in prev_sessions.items():
            if key not in sessions:
                data['del'].append({"ip": key, "os": val})

        session_file.write(dumps(data))


def run():
    """
    Main part of used components
    is steps:
    - load configuration
    - load password if is necessary and is missing in config file
    - create tmp file for neo4j
    loop:
    - download last flowmon data
    - analysis of data
    - load previous sessions
    - rewrite new sessions
    - upload data to DB
    - wait to next cycle
    :return: None
    """
    config = ConfigParser()
    config.read('config.ini')
    profile = config.get("Flowmon", "profile")
    channels = eval(config.get("Flowmon", "channels"), {}, {})
    filter = config.get('Flowmon', 'filter')
    domain = config.get('Flowmon', 'domain')
    username = config.get('Flowmon', 'username')
    flowmon_pass = config.get('Flowmon', 'password')
    sessions_path = config.get('Neo4j', 'session_path')

    if not flowmon_pass:
        print('Enter your flowmon password:')
        flowmon_pass = getpass()

    if type(channels) == str:
        channels = [channels]

    with open(sessions_path, 'a') as session:
        session.write('')

    driver = configure('config.ini')
    prepare_DB(driver)
    now = round_time(datetime.now())
    while True:
        print('Start')
        flow = download(domain, username, flowmon_pass, now, profile, channels, filter)
        print(f'flows: {len(flow)}')
        if len(flow) == 10000:
            print("WARNING: you are at limit with rest output, try filter only HTTP/HTTPS or smaller IP address range")
        sessions = make_sessions(flow)
        print(f'sessions: {len(sessions)}')
        prev_sessions = get_prev_sessions(sessions_path)
        write_session(prev_sessions, sessions, now, sessions_path)
        print('Commit to database ...')
        update_DB(sessions_path, driver)
        print(f'{now} done')
        time_diff = 300 - ((datetime.now() - now).total_seconds() % 300)
        # 10 seconds as time reserve
        print(f'time to next loop: {int(time_diff) + 10} seconds')
        time.sleep(time_diff + 10)
        now = now + timedelta(minutes=5)


if __name__ == '__main__':
    run()

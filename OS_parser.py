#!/usr/bin/python3.6

import os
from datetime import datetime, timedelta
from os.path import isfile, join
from Utils import *

'''--------------------------------------------CONNECT FLOW WITH ID BY EDUROAM LOG----------------------------------'''


# connect flows with session id from eduroam
def append_session_id():
    with open(flow_path, 'r') as flow:
        flow_path_new = flow_path[:-4] + "_id.csv"
        with open(flow_path_new, 'w') as new_flow:
            # skip first 3 lines
            new_flow.write(flow.readline()[:-1] + '%session_id;\n')

            for traffic_line in flow:
                ip = get_ip(traffic_line)
                traffic_time = get_time(traffic_line)
                if ip not in sessions_dict:
                    continue

                for session in sessions_dict[ip]:
                    if is_between(traffic_time, session[1:3]):
                        new_flow.write(traffic_line[:-2] + session[0] + ';\n')
                        break


'''------------------------------------CONNECT FLOW WITH OS BY DNS AND UPDATES SERVERS------------------------------'''


def append_os_by_specific_domains():
    with open(flow_path, 'r') as flow:
        new_flow_path = flow_path[:-4] + '_out.csv'
        with open(new_flow_path, 'w') as new_flow:
            new_flow.write(flow.readline()[:-1] + '%OS_specific_domains;\n')

            for traffic_line in flow:
                new_flow.write(traffic_line[:-1] + check_os(traffic_line))
'''------------------------------------CONNECT FLOW WITH OS BY TCP STACK------------------------------'''


def append_os_by_ttl():
    with open(flow_path, 'r') as flow:
        new_flow_path = flow_path[:-4] + "_out.csv"
        with open(new_flow_path, 'w') as new_flow:
            flow.seek(0)
            new_flow.write(flow.readline()[:-1] + '%TCP STACK;\n')

            for traffic_line in flow:
                array = traffic_line.split(';')
                if array[15] != 'N/A' and array[14] != 'N/A' and array[16] != 'N/A':
                    if int(array[16]) > 64:
                        ttl = 128
                    else:
                        ttl = 64
                    try:
                        new_flow.write(
                            traffic_line[:-1] + repr(fingers_dict[int(array[15])][int(array[14])][ttl][0][1]) + ';\n')
                    except KeyError:
                        new_flow.write(traffic_line[:-1] + ';\n')
'''------------------------------------EXTENDED FLOW------------------------------'''


def append_final_OS():
    with open(flow_path, 'r') as flow:
        new_flow_path = flow_path[:-4] + "_out.csv"
        with open(new_flow_path, 'w') as new_flow:
            new_flow.write(flow.readline()[:-1] + 'ID;OS;\n')
            for line in flow:
                array = line.split(';')
                info = array[0] + ';' + array[1] + ';' + array[3] + ';' + array[5] + ';'

                # ua
                ua = ''
                if array[10] != 'N/A':
                    ua = array[10]
                    if array[11] != 'N/A':
                        ua += ' ' + array[11]
                        if array[12] != 'N/A':
                            ua += '.' + array[12]
                ua_f = {}
                if ua != '':
                    ua_f[ua] = 1
                #  DNS
                dns = check_os(line)
                dns_f = []
                if dns != '':
                    dns_f = [dns]
                # tcp
                tcp = ''
                if array[14] != 'N/A' and array[15] != 'N/A' and array[16] != 'N/A':
                    if int(array[16]) <= 64:
                        ttl = 64
                    else:
                        ttl = 128
                    try:
                        tcp = int(fingers_dict[int(array[15])][int(array[14])][ttl][0][0])
                    except KeyError:
                        tcp = ''

                tcp_f = {}
                if tcp != '':
                    tcp_f[tcp] = 1
                fin_os = final_os([ua_f, tcp_f, dns_f])
                new_flow.write(info + array[21] + ';' + fin_os + ';\n')


# add session ID; OS by DNS and OS by TCP stack on end of each line
def append_all():
    with open(flow_path, 'r') as flow:
        new_flow_path = flow_path[:-4] + "_out.csv"
        with open(new_flow_path, 'w') as new_flow:
            # skip first 3 lines
            new_flow.write(flow.readline()[:-1] + 'SESSION_ID;OS_DNS_Domains;TCP STACK;\n')

            for traffic_line in flow:
                # id
                result = ''
                traffic_ip = get_ip(traffic_line)
                if traffic_ip in eduroam_dict:
                    traffic_time = get_time(traffic_line)
                    for session in eduroam_dict[traffic_ip]:
                        if is_between(traffic_time, session[1]):
                            result = traffic_line[:-1] + session[0] + ';'

                # eduroam log don't contains all ip from flow
                if result == '':
                    result = traffic_line[:-1] + ';'

                # DNS
                result += check_os(traffic_line) + ';'

                # TCP
                array = traffic_line.split(';')
                if array[15] != 'N/A' and array[14] != 'N/A' and array[16] != 'N/A':
                    if int(array[16]) > 64:
                        ttl = 128
                    else:
                        ttl = 64
                    try:
                        result += (repr(fingers_dict[int(array[15])][int(array[14])][ttl][0][1]) + ';')
                    except KeyError:
                        result += ';'
                new_flow.write(result + '\n')

'''----------------------------------------------CREATE SESSION SKELETON--------------------------------------------'''


# create file "sessions.csv" from flow which contains sessionID from eduroam log
def create_skeleton():
    with open(flow_path, 'r') as flow:
        with open('sessions.csv', 'w') as session_file:
            # skip first 3 lines
            flow.readline()

            session_file.write('ID;start;end;IP;\n')
            sessions = []
            for traffic_line in flow:
                traffic_ip = get_ip(traffic_line)
                if traffic_ip in eduroam_dict:
                    traffic_time = get_time(traffic_line)
                    for session in eduroam_dict[traffic_ip]:
                        if is_between(traffic_time, session[1]):
                            result = session[0] + ';' + session[1][0] + ';' + session[1][1] + ';' + traffic_ip + ';\n'
                            if result not in sessions:
                                sessions.append(result)
                                session_file.write(result)
                            break
'''------------------------------------SESSION APPEND OS BY domains------------------------------------'''


def connect_flow_with_session_domains():
    with open(session_path, 'r') as session:
        session_head = session.readline()[:-1]
    with open(flow_path, 'r') as flows:
        new_session_path = session_path[:-4] + "_out.csv"
        with open(new_session_path, 'w') as sessions:
            flows.readline()

            origin_len = session_head.count(';')

            sessions.write(session_head + 'OS_by_DNS;\n')
            for flow in flows:
                flow_ip = get_ip(flow)
                OS = check_os(flow)
                if OS == 'N/A':
                    continue
                if flow_ip in sessions_dict:
                    for session in sessions_dict[flow_ip]:
                        if is_between(get_time(flow), [session[1], session[2]]):
                            if len(session) == origin_len:
                                session.append([])
                            if len(session) > origin_len and OS not in session[origin_len]:
                                session[origin_len].append(OS)
                                if len(session[origin_len]) > 1:
                                    session[origin_len] = merge_same_sub_os(session[origin_len])

            for ip in sessions_dict:
                for records in sessions_dict[ip]:
                    for record in records:
                        if type(record) == list:
                            for tmp in record:
                                sessions.write(tmp)
                            sessions.write(';\n')
                        else:
                            sessions.write(record + ';')

'''-------------------------------------------SYN,WIN,TTL fingers--------------------------------------------------'''

# prepare file for finger_dict
def calc_perc_with_aggregation_ttl():
    with open('fingersDB_sorted.csv', 'r') as fingers:
        with open('fingers_map.csv', 'w') as new_fingers:
            new_fingers.write('id;' + fingers.readline()[:-2] + ';percent in group;million flows\r\n')
            finger_lines = fingers.readlines()
            patern = finger_lines[0].split(';')[:3]
            group = []
            size_id = 1
            for line in finger_lines:
                patern_next = line.split(';')[:3]
                if patern != patern_next:
                    size_of_group = calc_one_group(group)
                    added_group_info = add_info(size_of_group, group)
                    if size_of_group >= 0:
                        # counter = 0
                        for tmp in added_group_info:
                            # counter += float(tmp.split(';')[7])
                            new_fingers.write(repr(size_id) + ';' + tmp)
                            # if counter >= 95:
                            #     break
                        size_id += 1
                    group = [line]
                    patern = patern_next

                else:
                    group.append(line)

            size_of_group = calc_one_group(group)
            if size_of_group > 50:
                added_group_info = add_info(size_of_group, group)
                for record in added_group_info:
                    new_fingers.write(repr(size_id) + ';' + record)
'''-----------------------------------------SYN,WIN,TTL fingers SESSIONS-------------------------------------------'''


# calc_perc_with_aggregation_ttl()
def connect_flow_with_session_TCP():
    with open(session_path, 'r') as session:
        session_head = session.readline()[:-1]
    with open(flow_path, 'r') as flows:
        new_session_path = session_path[:-4] + "_out.csv"
        with open(new_session_path, 'w') as sessions:
            flows.readline()
            flows.readline()
            flows.readline()
            origin_len = session_head.count(';')

            sessions.write(session_head + 'OS_by_TCP_STACK;\n')
            for flow in flows:
                array = flow.split(';')
                if array[15] != 'N/A' and array[14] != 'N/A' and array[16] != 'N/A':
                    if int(array[16]) > 64:
                        ttl = 128
                    else:
                        ttl = 64
                    try:
                        OS = fingers_dict[int(array[15])][int(array[14])][ttl]
                    except KeyError:
                        OS = ';'
                flow_ip = get_ip(flow)
                if OS == ';':
                    continue
                if flow_ip in sessions_dict:
                    for session in sessions_dict[flow_ip]:
                        if is_between(get_time(flow), [session[1], session[2]]):
                            if len(session) == origin_len:
                                session.append({})
                            if OS[0][0] not in session[origin_len]:
                                session[origin_len][OS[0][0]] = 1
                            else:
                                session[origin_len][OS[0][0]] += 1

            for ip in sessions_dict:
                for records in sessions_dict[ip]:
                    for record in records:
                        if type(record) == dict:
                            sessions.write(calc_os_from_tcp_group(record, False) + ';\n')
                        else:
                            sessions.write(record + ';')

'''-------------------------------------------UA from flow to SESSIONS-------------------------------------------'''


# merge OS with(out) version
def merge_os(record):
    delet = []
    for tmp1 in record:
        delete = False
        for tmp2 in record:
            if tmp1 in tmp2 and tmp1 != tmp2:
                record[tmp2] += record[tmp1]
                delete = True
        if delete:
            delet.append(tmp1)
    for d in delet:
        record.pop(d, None)
    return record


def connect_flow_with_session_ua():
    with open(session_path, 'r') as session:
        session_head = session.readline()[:-1]
    with open(flow_path, 'r') as flows:
        new_session_path = session_path[:-4] + '_out.csv'
        with open(new_session_path, 'w') as sessions:
            flows.readline()
            flows.readline()
            flows.readline()
            sessions.write(session_head + 'OS_BY_UA;\n')
            origin_len = session_head.count(';')

            for flow in flows:
                array = flow.split(';')
                OS = array[10]
                major = array[11]
                minor = array[12]
                if OS == 'N/A':
                    continue
                if major != 'N/A':
                    OS = OS + ' ' + major
                    if minor != 'N/A':
                        OS = OS + '.' + minor
                flow_ip = get_ip(flow)
                if flow_ip in sessions_dict:
                    for session in sessions_dict[flow_ip]:
                        if is_between(get_time(flow), [session[1], session[2]]):
                            if len(session) == origin_len:
                                session.append({})
                            if OS not in session[origin_len]:
                                session[origin_len][OS] = 1
                            else:
                                session[origin_len][OS] += 1

            for ip in sessions_dict:
                for records in sessions_dict[ip]:
                    line = ''
                    for record in records:
                        if type(record) == dict:
                            merge = merge_os(record)
                            calc = 0
                            for tmp in merge:
                                calc += merge[tmp]
                            for tmp in merge:
                                line += (tmp + ' ' + ('%.2f' % (float(merge[tmp]*100)/calc)) + ', ')
                            line += ';'
                        else:
                            line += record + ';'
                    if len(records) == origin_len:
                        line += ';'
                    sessions.write(line + '\n')
'''---------------------------------------------------RESULT--------------------------------------------------------'''


# calc UA, TCP, DNS and FINAL OS with % in one loop
def make_result():
    with open(session_path, 'r') as session:
        session_head = session.readline()[:-1]
    with open(flow_path, 'r') as flows:
        new_session_path = session_path[:-4] + '_out.csv'
        with open(new_session_path, 'w') as sessions:
            flows.readline()

            sessions.write(session_head + 'OS_BY_UA;OS_BY_TCP;OS_BY_DNS;FINAL_OS;\n')
            origin_len = session_head.count(';')

            flow = flows.readline()
            while flow != '':
                try:
                    flow = flows.readline()
                except UnicodeDecodeError:
                    print(f'invalid line {flow[:19]}')
                    continue
                array = flow.split(';')
                if len(array) <= 21 or array[20] not in sessions_dict_id:
                    continue
                session = sessions_dict_id[array[20]]

                if len(session) == origin_len:
                    session.append({})
                    session.append({})
                    session.append({})

                # UA
                OS = array[10]
                major = array[11]
                minor = array[12]
                if OS != 'N/A':
                    if major != 'N/A':
                        OS = OS + ' ' + major
                        if minor != 'N/A':
                            OS = OS + '.' + minor
                    if OS not in session[origin_len]:
                        session[origin_len][OS] = 1
                    else:
                        session[origin_len][OS] += 1

                # TCP
                if array[15] != 'N/A' and array[14] != 'N/A' and array[16] != 'N/A':
                    if int(array[16]) > 64:
                        ttl = 128
                    else:
                        ttl = 64
                    try:
                        OS = fingers_dict[int(array[15])][int(array[14])][ttl]
                        if OS[0][0] not in session[origin_len + 1]:
                            session[origin_len + 1][OS[0][0]] = 1
                        else:
                            session[origin_len + 1][OS[0][0]] += 1
                    except KeyError:
                        pass

                #     DNS
                OS = check_os(flow)
                if OS != '':
                    if OS not in session[origin_len + 2]:
                        session[origin_len + 2][OS] = 1
                    else:
                        session[origin_len + 2][OS] += 1

            for record in sessions_dict_id.values():
                if len(record) == 4:
                    print(record)
                    continue

                result = record[0] + ';' + record[1] + ';' + record[2] + ';' + record[3] + ';'
                # UA
                result += return_MVP_element(record[4]) + ';'
                # print(( record
                # TCP
                if record[5] != {}:
                    result += (calc_os_from_tcp_group(record[5], False))
                result += ';'

                # DNS
                result += return_MVP_element(record[6]) + ';'

                # FINAL OS
                result += final_os(record[4:7]) + ';\n'
                sessions.write(result)


# split OS name on vendor and versions
def split_OS_from_result():
    with open(session_path, 'r') as session_in:
        with open(session_path[:-4] + '_out.csv', 'w') as session_out:
            session_out.write('ID;start;end;IP;UA_Vendor;UA_OS_name;UA_major;UA_minor;TCP_Vendor;TCP_OS_name;TCP_major;TCP_minor;Domain_Vendor;Domain_OS_name;DHCP_Vendor;DHCP_OS_name;Final_OS;Mac;\n')
            session_in.readline()
            for line in session_in:
                # session_out.write(line)
                array = line.split(';')
                result = array[0] + ';' + array[1] + ';' + array[2] + ';' + array[3] + ';'
                result += split_OS(array[4], 4)
                result += split_OS(array[5].split(',')[0], 4)
                result += split_OS(array[6], 2)
                result += split_OS(array[8], 2)
                result += array[7] + ';'
                result += array[9] + ';\n'
                session_out.write(result)


def append_OS_by_DHCP():
    with open(session_path, 'r') as session_in:
        with open(session_path[:-4] + '_out.csv', 'w') as session_out:
            session_out.write(session_in.readline()[:-1] + 'OS_BY_DHCP;MAC;\n')
            for line in session_in:
                result = ';;\n'
                session_ip = get_ip(line)
                if session_ip in dhcp_dict:
                    session_time = get_time(line)
                    choices = []
                    for tmp in dhcp_dict[session_ip]:
                        if session_time[0] <= tmp[1] and session_time[1] >= tmp[0]:
                            choices.append(tmp)
                    if len(choices) == 1:
                        result = choices[0][2] + ';' + choices[0][3] + ';\n'
                    elif len(choices) > 1:
                        final = []
                        mac = ''
                        for record in choices:
                            if record[0] != record[1]:
                                if record[2] not in final:
                                    mac = record[3]
                                    final.append(record[2])
                        if len(final) == 1:
                            result = final[0] + ';' + mac + ';\n'
                session_out.write(line[:-1] + result)


# experimental without eduroam log
def create_session_from_flow_by_time():
    with open(flow_path, 'r') as flow:
        with open(flow_path[:-4] + '_out.csv', 'w') as session:
            flow.readline()
            session.write('ID;start;end;IP;name;mac;session_id\n')
            actual_sessions = {}
            my_id = 1
            for line in flow:
                flow_id = line.split(';')[21]
                ip = get_ip(line)
                my_time = get_time(line)
                mac = ''
                name = eduroam_name_dict[flow_id]
                if flow_id in mac_dict:
                    mac = mac_dict[flow_id]
                # new session by ip
                if ip not in actual_sessions:
                    actual_sessions[ip] = [my_id, my_time[0], my_time[1], [name], [mac], [flow_id]]
                    my_id += 1
                    continue
                # new session after 5 minutes
                if actual_sessions[ip][2] in time_dict and time_dict[actual_sessions[ip][2]] < my_time[0]:
                    record = actual_sessions[ip]
                    # print(( record
                    session.write(repr(record[0]) + ';' + record[1] + ';' + record[2] + ';' + ip + ';' + repr(
                        record[3]) + ';' + repr(record[4]) + ';' + repr(record[5]) + ';\n')
                    my_id += 1
                    actual_sessions[ip] = [my_id, my_time[0], my_time[1], [name], [mac], [flow_id]]
                    continue
                actual_sessions[ip][2] = my_time[1]
                if mac != '' and mac not in actual_sessions[ip][4]:
                    if '' in actual_sessions[ip][4]:
                        actual_sessions[ip][4][0] = mac
                    else:
                        actual_sessions[ip][4].append(mac)
                if name not in actual_sessions[ip][3]:
                    actual_sessions[ip][3].append(name)
                if flow_id not in actual_sessions[ip][5]:
                    actual_sessions[ip][5].append(flow_id)
            for ip in actual_sessions:
                record = actual_sessions[ip]
                session.write(repr(record[0]) + ';' + record[1] + ';' + record[2] + ';' + ip + ';' + repr(
                    record[3]) + ';' + repr(record[4]) + ';' + repr(record[5]) + ';\n')


def get_OS_by_UA(data):
    if len(data) != 3:
        return ''
    result = ''
    if data[0] != 'N/A':
        result += data[0]
        if data[1] != 'N/A':
            result += ' ' + data[1]
            if data[2] != 'N/A':
                result += '.' + data[2]
    return result


def get_OS_by_tcp(array):
    if len(array) != 3:
        return ''
    OS = ''
    # TCP
    weight = 0

    if array[1] != 'N/A' and array[0] != 'N/A' and array[2] != 'N/A':
        if int(array[2]) > 64:
            ttl = 128
        else:
            ttl = 64
        try:
            OS = get_OS_by_UA(fingers_dict[int(array[1])][int(array[0])][ttl][0][1])
            weight = float(fingers_dict[int(array[1])][int(array[0])][ttl][0][2])/5
        except KeyError:
            OS = ''
    return [OS, weight]


def create_session_from_flow():
    with open(flow_path, 'r') as flow:
        with open(flow_path[:-4] + '_test_with_history.csv', 'w') as session:
            flow.readline()
            session.write('ID;start;end;IP;name;mac;session_id\n')
            actual_sessions = {}
            done_sessions = {}
            history_sessions = []
            os_counter = 0
            my_id = 1
            for line in flow:
                array = line.split(';')
                ip = array[3]
                flow_id = array[21]
                OS_domain = [check_os(line), 50]
                OS_ua = [get_OS_by_UA(array[10:14]), 20]
                OS_tcp = get_OS_by_tcp(array[14:17])
                OS_mix = OS_ua
                my_time = get_time(line)
                true_OS = ''
                if flow_id in sessions_dict_with_os:
                    true_OS = sessions_dict_with_os[flow_id]
                mac = ''
                name = eduroam_name_dict[flow_id]
                if flow_id in mac_dict:
                    mac = mac_dict[flow_id]
                # new session by ip
                if ip not in actual_sessions:
                    actual_sessions[ip] = [my_id, my_time[0], my_time[1], OS_mix[0], 300, [name], [mac], [flow_id], [true_OS]]
                    my_id += 1
                    continue
                actual_sessions[ip][2] = my_time[1]
                for OS in [OS_ua, OS_domain, OS_tcp]:
                    OS_name = OS[0]
                    OS_weight = OS[1]
                    if OS_name != '':
                        if actual_sessions[ip][3] == '':
                            actual_sessions[ip][3] = OS_name
                        if OS_name in actual_sessions[ip][3] or actual_sessions[ip][3] in OS_name:
                            if mac != '' and mac not in actual_sessions[ip][6]:
                                if '' in actual_sessions[ip][6]:
                                    actual_sessions[ip][6][0] = mac
                                else:
                                    actual_sessions[ip][6].append(mac)
                            if flow_id not in actual_sessions[ip][7]:
                                actual_sessions[ip][7].append(flow_id)
                                if name not in actual_sessions[ip][5]:
                                    actual_sessions[ip][5].append(name)
                                actual_sessions[ip][8].append(true_OS)
                            if actual_sessions[ip][4] < 300:
                                actual_sessions[ip][4] += float(OS_weight)
                                actual_sessions[ip][2] = my_time[1]
                        else:
                            actual_sessions[ip][4] -= float(OS_weight)
                            history_sessions.append(line)
                            if actual_sessions[ip][4] <= 0:
                                my_id += 1
                                record = actual_sessions[ip]
                                if (datetime.datetime.strptime(record[2], "%Y-%m-%d %H:%M:%S") - datetime.datetime.strptime(
                                        record[1], "%Y-%m-%d %H:%M:%S")) >= datetime.timedelta(minutes=1):
                                    os_counter += 1
                                    if ip not in done_sessions:
                                        done_sessions[ip] = [record[1], record[2]]
                                    else:
                                        done_sessions[ip].append([record[1], record[2]])
                                    session.write(repr(record[0]) + ';' + record[1] + ';' + record[2] + ';' + ip + ';' + record[3]
                                                  + ';' + repr(record[5]) + ';' + repr(record[6]) + ';' + repr(record[7]) + ';' + repr(record[8]) + ';\n')
                                actual_sessions[ip] = [my_id, my_time[0], my_time[1], OS_mix[0], 300, [name], [mac], [flow_id], [true_OS]]

            for ip in actual_sessions:
                record = actual_sessions[ip]
                if (datetime.datetime.strptime(record[2], "%Y-%m-%d %H:%M:%S") - datetime.datetime.strptime(
                        record[1], "%Y-%m-%d %H:%M:%S")) >= datetime.timedelta(minutes=1):
                    session.write(repr(record[0]) + ';' + record[1] + ';' + record[2] + ';' + ip + ';' + record[3]
                                  + ';' + repr(record[5]) + ';' + repr(record[6]) + ';' + repr(record[7]) + ';' + repr(record[8]) + ';\n')


# test for specific domains
def domain_test():
    with open(flow_path, 'r') as flow:
        url = 'address.com'
        print(url)
        ids = []
        for line in flow:
            if url in line:
                if (line.split(';')[21]) not in ids:
                    ids.append(line.split(';')[21])
        for tmp in ids:
            if tmp in sessions_dict_id:
                print(sessions_dict_id[tmp])


# test with generating new sessions every 5 minutes
def make_sessions_every_5_min(actual_file_path, my_time):
    with open(actual_file_path, 'r') as flows:
        flows.readline()
        sessions = {}

        prev_output_base = 'tmp/' + (my_time - timedelta(minutes=5)).strftime('%Y%m%d%H%M')
        prev_session = get_prev_session(prev_output_base)
        for line in flows:
            array = line.split(';')
            if array[2] == 'ICMP':
                continue
            ip = array[3]
            if ip not in sessions:
                sessions[ip] = [{}, {}, {}]

            session = sessions[ip]
            # UA
            OS = array[10]
            major = array[11]
            minor = array[12]
            if OS != 'N/A':
                if major != 'N/A':
                    OS = OS + ' ' + major
                    if minor != 'N/A':
                        OS = OS + '.' + minor
                if OS not in session[0]:
                    session[0][OS] = 1
                else:
                    session[0][OS] += 1

            # TCP
            if array[15] != 'N/A' and array[14] != 'N/A' and array[16] != 'N/A':
                if int(array[16]) > 64:
                    ttl = 128
                else:
                    ttl = 64
                try:
                    OS = fingers_dict[int(array[15])][int(array[14])][ttl]
                    if OS[0][0] not in session[1]:
                        session[1][OS[0][0]] = 1
                    else:
                        session[1][OS[0][0]] += 1
                except KeyError:
                    pass

            # DNS
            OS = check_os(line)
            if OS != '':
                if OS not in session[2]:
                    session[2][OS] = 1
                else:
                    session[2][OS] += 1

        output_path = f"tmp/{time.strftime('%Y%m%d%H%M')}"
        return write_sessions(output_path, sessions, prev_session)


'''---------------------------------------------------METHODS--------------------------------------------------------'''
# make_result()
# append_OS_by_DHCP()
# split_OS_from_result()

# make_sessions_every_5_min()
# create_session_from_flow()
# create_session_from_flow_by_time()
# remove_without_session_id()
# dns_test()
# create extended flows
# append_all()

'''CLEAN and SEARCH'''
# for quick search in files
# quick_select()

# remove from eduroam connections with zero bytes
# clean_eduroam_log()

# remove flows with invalid url
# clean_flows()

'''EXTEND FLOWS'''
# append session_id to flow
# append_session_id()

# append os by DNS and updates to flow
# append_os_by_updates()

# append os by tcp ip stack to flow file
# append_os_by_ttl()


'''AGGREGATE TO EDUROAM SESSIONS'''
# create new file 'sessions.csv' where aggregate sessions id from flows
# create_skeleton()

# connect_flow_with_session_ua()
# connect_flow_with_session_TCP()
# connect_flow_with_session_DNS()

# make_result()

''' OTHER '''
# filtered TCP IP stack
# calc_perc_with_aggregation_ttl()

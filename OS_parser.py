from Utils import *

'''--------------------------------------------CONNECT FLOW WITH ID BY EDUROAM LOG----------------------------------'''


# connect flows with session from eduroam
def append_session_id_by_eduroam():
    with open(flow_path, 'r') as flow:
        flow_path_new = flow_path[:-4] + "_first_10_min.csv"
        with open(flow_path_new, 'w') as new_flow:
            new_flow.write(flow.readline()[:-1] + '%session_id;\n')

            for traffic_line in flow:
                traffic_ip = get_ip(traffic_line)
                if traffic_ip in eduroam_dict:
                    traffic_time = get_time(traffic_line)
                    for session in eduroam_dict[traffic_ip]:
                        if is_between(traffic_time, session[1]):
                            new_flow.write(traffic_line[:-1] + session[0] + ';\n')
                            break
                # eduroam log don't contains all ip from flow
                else:
                    new_flow.write(traffic_line[:-1] + ';\n')


# connect flows with session from eduroam
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


def append_os_by_updates():
    with open(flow_path, 'r') as flow:
        new_flow_path = flow_path[:-4] + '_out.csv'
        with open(new_flow_path, 'w') as new_flow:
            new_flow.write(flow.readline()[:-1] + '%OS_DNS_Domains;\n')

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
                if array[10] != 'N/A' :
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
                    if array[16] <= 64:
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

                os = final_os([ua_f, tcp_f, dns_f])
                new_flow.write(info + array[21] + ';'+ os + ';\n')


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

                # session log don't contains all ip from flow
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

'''------------------------------------SESSION, APPEND OS BY DNS------------------------------------'''


def connect_flow_with_session_DNS():
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


# get one OS with version and percents from flow record by TCP stack
def calc_os_from_tcp_group(record, raw):
    OS = {}
    total = 0
    for tmp in record.values():
        total += tmp
    for id in record:
        tmp = fingers_dict_id[int(id)]
        for curr_os in tmp:
            if curr_os[0] in OS:
                OS[curr_os[0]] += float(curr_os[1]) * record[id] / total
            else:
                OS[curr_os[0]] = float(curr_os[1]) * record[id] / total
    maxx = 0
    result = None
    div = 0
    if raw:
        return OS
    for eos in OS:
        div += float(OS[eos])
        if float(OS[eos]) > maxx:
            result = eos
            maxx = float(OS[eos])
    maxx = maxx * 100 / div
    return result + ', ' + ('%.3f' % round(maxx, 3))


def get_number(line):
    return line.split(';')[6][:-2]


# prepare file for finger_dict calc size of one group
def calc_one_group(group):
    counter = 0
    for record in group:
        counter += int(get_number(record))
    return counter


'''-----------------------------------------SYN,WIN,TTL fingers SESSIONS-------------------------------------------'''


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


def split_raw_line(line):
    array = line.split(';')
    result = array[0] + ';' + array[1] + ';' + array[2] + ';' + array[3] + ';'
    result += split_OS(array[4], 4)
    result += split_OS(array[5].split(',')[0], 4)
    result += split_OS(array[6], 2)
    result += array[7] + ';\n'
    return result


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
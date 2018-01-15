#!/usr/bin/python3.6

import argparse
from Utils import *
from OS_parser import split_raw_line


def run(flow_path, session_path, output_path, TCP_finger_path, extend):
    """
    Parse every line from flow file, connect it with session by ID and determine OS by every method.

    @param flow_path: network flow for analyse.
    @param session_path: session file contains data about time and IP.
    @param output_path: output file path.
    @param TCP_finger_path: TCP parameters dataset (TTL, SYN size, TCP window size) joined with OS.
    @param extend: flag (True/False) if you want split OS in output.

    """
    with open(flow_path, 'r') as flows:
        with open(output_path, 'w') as sessions:
            flows.readline()
            if extend:
                sessions.write('ID;start;end;IP;UA_Vendor;UA_OS_name;UA_major;UA_minor;TCP_Vendor;TCP_OS_name;TCP_major;TCP_minor;Domain_Vendor;Domain_OS_name;Final_OS;\n')
            else:
                sessions.write('ID;start;end;IP;OS_BY_UA;OS_BY_TCP;OS_BY_DNS;FINAL_OS;\n')
            origin_len = 4

            fingers_dict = create_fingers_dict(TCP_finger_path)
            fingers_dict_id = create_fingers_dict_id(TCP_finger_path)
            sessions_dict_id = create_session_dict_by_id(session_path)
            for flow in flows:
                array = flow.split(';')
                if array[20] not in sessions_dict_id:
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

                OS = ''
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
                        OS = ''

                # domains
                OS = check_os(flow)
                if OS != '':
                    if OS not in session[origin_len + 2]:
                        session[origin_len + 2][OS] = 1
                    else:
                        session[origin_len + 2][OS] += 1

            for record in sessions_dict_id.values():
                if len(record) == 4:
                    continue

                result = record[0] + ';' + record[1] + ';' + record[2] + ';' + record[3] + ';'
                # UA
                result += return_MVP_element(record[4]) + ';'

                # TCP
                if record[5] != {}:
                    result += (calc_os_from_tcp_group(record[5], False, fingers_dict_id))
                result += ';'

                # Domain
                result += return_MVP_element(record[6]) + ';'

                # FINAL OS
                result += final_os(record[4:7], fingers_dict_id) + ';\n'

                if extend:
                    sessions.write(split_raw_line(result))
                else:
                    sessions.write(result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', help='<flow path>')
    parser.add_argument('-s', help='<session path>')
    parser.add_argument('-t', help='<tcp map path>')
    parser.add_argument('-o', help='<output path>')
    parser.add_argument('-e', help='extended output mode', action='store_true')

    args = parser.parse_args()

    flow_path = args.f if args.f else 'Dataset/anonymized_flow.csv'
    session_path = args.s if args.s else 'Dataset/anonymized_sessions.csv'
    TCP_finger_path = args.t if args.t else 'fingers_map.csv'
    output_path = args.o if args.o else 'Dataset/output.csv'
    extend = args.e

    run(flow_path, session_path, output_path, TCP_finger_path, extend)

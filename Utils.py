import re

major_minor_reg = re.compile('\d*\.\d*')

# Windows
win_version = re.compile('(?<=windows)\d+\.\d+')
win_reg1 = re.compile('update\.microsoft\.com')
# DNS query
win_reg2 = re.compile('download.windowsupdate.com')
win_reg3 = re.compile('weather\.microsoft\.com')
# IE connection
win_reg4 = re.compile('client\.wns\.windows\.com')
win_reg5 = re.compile('msftconnecttest\.com')
win_reg6 = re.compile('watson\.telemetry\.microsoft\.com')
win_reg7 = re.compile('statsfe2\.update\.microsoft\.com')
win_reg8 = re.compile('dmd\.metaservices\.microsoft\.com')
win_reg9 = re.compile('msftncsi\.com')
win_reg10 = re.compile('ctldl\.windowsupdate\.com')
win_reg11 = re.compile('microsoft\.com\.nsatc\.net')
win_reg12 = re.compile('login\.live\.com')
win_reg13 = re.compile('dl\.delivery\.mp\.microsoft\.com')
win_reg14 = re.compile('au\.windowsupdate\.com')
win_reg15 = re.compile('vortex-win\.data\.microsoft\.com')
win_reg16 = re.compile('g\.ceipmsn\.com')
win_reg17 = re.compile('cdn\.content\.prod\.cms\.msn\.com')
win_reg18 = re.compile('-pro.d.dsp.mp.microsoft.com')
win_reg19 = re.compile('au.download.windowsupdate.com')
win_reg20 = re.compile('settings-win.data.microsoft.com')
win_reg21 = re.compile('e-service.weather.microsoft.com')
win_reg22 = re.compile('settings-win.data.microsoft.com')
win_reg23 = re.compile('g.ceipmsn.com')
win_reg24 = re.compile('msn-com.akamaized.net')
win_reg25 = re.compile('am.microsoft.com')
win_reg26 = re.compile('arc.msn.com')
win_reg27 = re.compile('sls.update.microsoft.com')
win_reg28 = re.compile('oem.twimg.com')
win_reg29 = re.compile('urs.smartscreen.microsoft.com')
win_reg30 = re.compile('dsp.mp.microsoft.com')
win_reg31 = re.compile('activity.windows.com')
win_reg32 = re.compile('ocsp.msocs\.com')
win_reg33 = re.compile('vl\.ff\.avast\.com')

# MAC OS and OS X
mac_reg1 = re.compile('swscan\.apple\.com')
mac_reg2 = re.compile('swcdn\.apple\.com')
# OS X 10.8+ few collisions with windows (iTunes)
mac_reg3 = re.compile('swdist\.apple\.com')
# icloud servers
mac_reg4 = re.compile('\.icloud\.com')
mac_reg5 = re.compile('cl[1-5]\.apple.com')
mac_reg6 = re.compile('gs-loc.apple.com')
mac_reg7 = re.compile('itunes.apple.com')
mac_reg8 = re.compile('.push.apple.com')
mac_reg9 = re.compile('xp.apple.com')
mac_reg10 = re.compile('captive.apple.com')
mac_reg11 = re.compile('configuration.apple.com')
mac_reg12 = re.compile('ssl.ls.apple.com')
mac_reg13 = re.compile('mesu.apple.com')
mac_reg14 = re.compile('guzzoni.apple.com')
mac_reg15 = re.compile('.ls.apple.com')
mac_reg16 = re.compile('pancake.apple.com')

# Linux
# canonical net 91.189.88.0/21
canonical_net = re.compile('91\.189\.(?:88|89]|9[0-5]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
# updates sites from canonical
linux_reg1 = re.compile('canonical\.com')
# updates sites from ubunu
linux_reg2 = re.compile('security\.ubuntu\.com')
linux_reg3 = re.compile('archive\.ubuntu\.com')
# Ubuntu error tracker submission, it makes a DNS query for daisy.ubuntu.com on every boot
linux_reg4 = re.compile('daisy\.ubuntu\.com')
# Ubuntu NTP server, it makes a DNS query for ntp.ubuntu.com on every boot
linux_reg5 = re.compile('ntp\.ubuntu\.com')
# maybe
linux_reg6 = re.compile('ubuntu\.pool\.ntp\.org')

# Android
android_reg1 = re.compile('connectivitycheck\.android\.com')
android_reg2 = re.compile('connectivitycheck\.gstatic\.com')
android_reg3 = re.compile('android\.pool\.ntp\.org')
android_reg4 = re.compile('api.sec.miui.com')
android_reg5 = re.compile('android\.clients\.google\.com')
android_reg6 = re.compile('clients3\.google\.com;;/generate_204')
android_reg7 = re.compile('cloudconfig\.googleapis\.com')
android_reg8 = re.compile('helpnewsrepublic1.ksmobile.com')
android_reg9 = re.compile('portal.fb.com')
android_reg10 = re.compile('mqtt-mini.facebook.com')
android_reg11 = re.compile('[^8]api.accuweather.com')
android_reg12 = re.compile('data.mistat.xiaomi.com')
android_reg13 = re.compile('ms.cmcm.com')
android_reg14 = re.compile('cmdts.ksmobile.com')
android_reg15 = re.compile('micloud.xiaomi.net')

# Fedora
fed_reg1 = re.compile('fedoraproject\.org;;/static/hotspot\.txt')

# Blackberry
bb_reg1 = re.compile('icc\.blackberry\.com')
bb_reg2 = re.compile('inet\.icrs\.blackberry\.com')

'''--------------------------------------------------METHODS--------------------------------------------------'''


def get_vendor(str):
    if 'Android' in str:
        return 'Google'
    if 'Windows' in str:
        return 'Microsoft'
    if 'Mac' in str or 'iOS' in str or 'Darwin' in str:
        return 'Apple'
    if 'Ubuntu' in str or 'Linux' in str or 'Fedora' in str:
        return 'Linux/Unix'
    if 'BlackBerry' in str:
        return 'BlackBerry'
    return ''


def get_vendor_OS_name(str):
    if 'Windows' in str:
        return 'Microsoft;Windows'
    if 'Windows Phone' in str:
        return 'Microsoft;Windows Phone'

    if 'Mac' in str:
        return 'Apple;Mac OS X'
    if 'iOS' in str:
        return 'Apple;iOS'
    if 'Darwin' in str:
        return 'Apple;Darwin'

    if 'Android' in str:
        return 'Google;Android'
    if 'Chrome OS' in str:
        return 'Google;Chrome OS'

    if 'Debian' in str:
        return 'Linux/Unix;Debian'
    if 'Ubuntu' in str:
        return 'Linux/Unix;Ubuntu'
    if 'Fedora' in str:
        return 'Linux/Unix;Fedora'
    if 'Linux' in str:
        return 'Linux/Unix;'

    if 'BlackBerry' in str:
        return 'Other;BlackBerry'

    if str != '':
        return 'Other;'
    return ';'


def get_major_minor(str):
    if not major_minor_reg.search(str):
        return ';'
    tmp = major_minor_reg.search(str).group(0).split('.')
    return tmp[0] + ';' + tmp[1]


def split_OS(OS, size):
    result = get_vendor_OS_name(OS) + ';'
    if size == 4:
        if 'Other' not in result:
            result += get_major_minor(OS) + ';'
        else:
            result += ';;'
    return result


# check if traffic was during session
def is_between(traffic_time, session_time):
    return traffic_time[0] >= session_time[0] and traffic_time[1] <= session_time[1]


# get session ID
def get_id(session_line):
    return session_line[:session_line.index(';')]


'''-------------------------------------------------------DICTIONARY------------------------------------------------'''

# create dictionary from session file by IP address
# usage : dict[ip_address] return list of sessions with same IP
def create_session_dict_by_ip():
    # path to eduroam session file
    with open(session_path, 'r') as sessions:
        # ignore first line
        sessions.readline()
        dict = {}
        for session in sessions:
            record = session.split(';')[:-1]
            if record[3] not in dict:
                dict[record[3]] = [record]
            else:
                dict[record[3]].append(record)
        return dict


# create dictionary from session file by IP address
# usage : dict[id] return current session with same ID
def create_session_dict_by_id(session_path):
    with open(session_path, 'r') as sessions:
        # ignore first line
        sessions.readline()
        dict = {}
        for session in sessions:
            dict[get_id(session)] = session.split(';')[:4]
        return dict


# create dictionary from TCP stack
# usage : dict[SYN][WIN][TTL] return array with OS and their %
def create_fingers_dict(finger_path ):
    with open(finger_path, 'r') as fingers:
        # ignore first line
        fingers.readline()
        result = {}
        for record in fingers:
            array = record.split(';')
            syn = int(array[1])
            win = int(array[2])
            ttl = int(array[3])
            try:
                # groups with more than 1 OS [SYN][WIN][TTL]
                result[syn][win][ttl].append([array[0], array[4:7], array[8]])
            except KeyError:
                if syn not in result:
                    result[syn] = {}
                if win not in result[syn]:
                    result[syn][win] = {}
                if ttl not in result[syn][win]:
                    result[syn][win][ttl] = [[array[0], array[4:7], array[8]]]
        return result


# usage : dict[id] return array with OS and their %
def create_fingers_dict_id(finger_path):
    with open(finger_path, 'r') as fingers:
        # ignore first line
        fingers.readline()
        result = {}
        for record in fingers:
            array = record.split(';')
            id = int(array[0])
            OS = array[4]
            major = array[5]
            minor = array[6]
            perc = array[8]
            if major != 'N/A':
                OS += ' ' + major
                if minor != 'N/A':
                    OS += '.' + minor
            if id in result:
                result[id].append([OS, perc])
            else:
                result[id] = [[OS, perc]]
        return result


def return_MVP_element(dic):
    max = 0
    element = ''
    for tmp in dic:
        if dic[tmp] > max:
            max = dic[tmp]
            element = tmp
    return element

'''------------------------------------CONNECT FLOW WITH OS BY DNS AND UPDATES SERVERS------------------------------'''


def is_win(record):
    return win_reg1.search(record) or win_reg2.search(record) or win_reg3.search(record) \
           or win_reg4.search(record) or win_reg5.search(record) or win_reg6.search(record) \
           or win_reg7.search(record) or win_reg8.search(record) or win_reg9.search(record) \
           or win_reg10.search(record) or win_reg11.search(record) or win_reg12.search(record) \
           or win_reg13.search(record) or win_reg14.search(record) or win_reg15.search(record) \
           or win_reg16.search(record) or win_reg17.search(record) or win_reg18.search(record) \
           or win_reg19.search(record) or win_reg20.search(record) or win_reg21.search(record) \
           or win_reg22.search(record) or win_reg23.search(record) or win_reg24.search(record) \
           or win_reg25.search(record) or win_reg26.search(record) or win_reg27.search(record) \
           or win_reg28.search(record) or win_reg29.search(record) or win_reg30.search(record) \
           or win_reg31.search(record) or win_reg32.search(record) or win_reg33.search(record)

def is_mac(record):
    return mac_reg1.search(record) or mac_reg2.search(record) or mac_reg3.search(record) \
            or mac_reg4.search(record) or mac_reg5.search(record) or mac_reg6.search(record) \
            or mac_reg7.search(record) or mac_reg8.search(record) or mac_reg9.search(record) \
            or mac_reg10.search(record) or mac_reg11.search(record) or mac_reg12.search(record) \
            or mac_reg13.search(record) or mac_reg14.search(record) or mac_reg15.search(record) \
            or mac_reg16.search(record)


def is_lin(record):
    return linux_reg1.search(record) or linux_reg2.search(record) or linux_reg3.search(record)\
           or linux_reg4.search(record) or linux_reg5.search(record) or linux_reg6.search(record)


def is_android(record):
    return android_reg1.search(record) or android_reg2.search(record) or android_reg3.search(record) \
            or android_reg4.search(record) or android_reg5.search(record) or android_reg6.search(record) \
            or android_reg7.search(record) or android_reg8.search(record) or android_reg9.search(record) \
            or android_reg10.search(record) or android_reg11.search(record) or android_reg12.search(record) \
            or android_reg13.search(record) or android_reg14.search(record) or android_reg15.search(record)


def is_fedora(record):
    return fed_reg1.search(record)


def is_blackberry(record):
    return bb_reg1.search(record) or bb_reg2.search(record)


def get_win_version(record):
    if win_version.search(record):
        return win_version.search(record).group(0) + ' '
    return ''


def check_os(record):
    if is_win(record):
        return 'Windows'
    if is_mac(record):
        return 'Mac'
    if is_lin(record):
        return 'Linux'
    if is_android(record):
        return 'Android'
    if is_blackberry(record):
        return 'BlackBerry'
    if is_fedora(record):
        return 'Fedora'
    return ''

'''----------------------------------TCP STACK-------------------------------------'''


# get one OS with version and percents from flow record by TCP stack
def calc_os_from_tcp_group(record, raw, fingers_dict_id):
    OS = {}
    total = 0
    for tmp in record.values():
        total += tmp
    for id in record:
        tmp = fingers_dict_id[int(id)]
        for curr_os in tmp:
            curr_os[0] = convert_win_version(curr_os[0])
            if curr_os[0] in OS:
                OS[curr_os[0]] += float(curr_os[1]) * record[id] / total
            else:
                OS[curr_os[0]] = float(curr_os[1]) * record[id] / total
    maxx = 0
    result = None
    if raw:
        return OS
    for eos in OS:
        if float(OS[eos]) > maxx:
            result = eos
            maxx = float(OS[eos])
    return result


def get_number(line):
    return line.split(';')[6][:-2]


# prepare file for finger_dict calc size of one group
def calc_one_group(group):
    counter = 0
    for record in group:
        counter += int(get_number(record))
    return counter

'''--------------------------------RESULTS--------------------------------------------'''
# remove % from record
def remove_UA(array):
    result = ''
    array = array.split(' ')[:-1]
    for tmp in array:
        result += tmp + ' '
    return result


# win_version : name
win_map ={'Windows 10.0': 'Windows 10',
            'Windows 6.3': 'Windows 8.1',
            'Windows 6.2': 'Windows 8',
            'Windows 6.1': 'Windows 7',
            'Windows 6.0': 'Windows Vista',
            'Windows 5.2': 'Windows XP Professional x64',
            'Windows 5.1': 'Windows XP',
            'Windows 5.0': 'Windows 2000'}


def convert_win_version(os):
    if os in win_map:
        return win_map[os]
    return os


def final_os(data, fingers_dict_id):
    if len(data) != 3:
        return ''
    ua = None
    tcp = None
    dns = None

    cou = 0
    if data[0] != {}:
        cou += 1
        ua = data[0]
    if data[1] != {}:
        cou += 1
        tcp = data[1]
    if data[2] != []:
        cou += 1
        dns = data[2]
    if cou == 0:
        return ''

    result = {}

    # add tcp percents
    if tcp != None:
        result = calc_os_from_tcp_group(tcp, True, fingers_dict_id)

    # add ua percents:
    if ua != None:
        ua_size = 0
        for tmp in ua:
            ua_size += ua[tmp]
        for tmp in ua:
            name = convert_win_version(tmp)
            if tmp in result:
                result[name] += float(100*ua[tmp]/ua_size)
            else:
                result[name] = float(100*ua[tmp]/ua_size)

    # add DNS percents:
    if dns != None:
        for OS in dns:
            if '.' not in OS and OS != '':
                set = False
                for OS_result in result:
                    if OS in OS_result:
                        result[OS_result] += float(100)/len(dns)
                        set = True
                if not set:
                    result[OS] = float(100)/len(dns)
    final_os = ''
    max = 0
    apple = 0
    darwin = 0
    iOS = 0
    Mac = 0
    for OS in result:
        if 'Darwin' in OS:
            apple += result[OS]
            darwin += result[OS]
        elif 'iOS' in OS:
            iOS += result[OS]
            darwin += result[OS]
        elif 'Mac OS X' in OS:
            apple += result[OS]
            Mac += result[OS]
        if result[OS] > max:
            final_os = OS
            max = result[OS]

    if 'Darwin' in final_os or 'iOS' in final_os or 'Mac' in final_os :
        return final_os

    if apple > (max * 5):
        if Mac >= darwin and Mac >= iOS:
            return 'Mac OS X'
        if iOS >= darwin:
            return 'iOS'
        return 'Darwin'
    return final_os


# remove version from OS
def delete_major_minor(record):
    if 'Mac' in record or 'iOS' in record or 'Darwin' in record or 'OS X' in record:
        return 'Mac'
    if 'Win' in record:
        return 'Windows'
    if 'Debian' in record or 'Ubuntu' in record or 'Fedora' in record or 'Linux' in record:
        return 'Linux'
    if 'Android' in record:
        return 'Android'
    return None

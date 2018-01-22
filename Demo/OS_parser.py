import re
from configparser import ConfigParser

# Windows
win_version = re.compile('(?<=windows)\d+\.\d+')
win_reg1 = re.compile('update\.microsoft\.com')
# DNS query
win_reg2 = re.compile('download.windowsupdate.com')
# maybe
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

# MAC OS X, iOS and Darwin
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
# connectivitycheck for android 5 or older
android_reg1 = re.compile('connectivitycheck\.android\.com')
# connectivitycheck for android 6 or newer
android_reg2 = re.compile('connectivitycheck\.gstatic\.com')
# DNS query for default NTP android 5 or older
android_reg3 = re.compile('android\.pool\.ntp\.org')
# DNS query for default NTP android 6 or newer
android_reg4 = re.compile('api.sec.miui.com')
android_reg5 = re.compile('android\.clients\.google\.com')
android_reg6 = re.compile('clients3\.google\.com/generate_204')
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
fed_reg1 = re.compile('fedoraproject\.org/static/hotspot\.txt')

# Blackberry
bb_reg1 = re.compile('icc\.blackberry\.com')
bb_reg2 = re.compile('inet\.icrs\.blackberry\.com')

'''-------------------------------------------------------DICTIONARY------------------------------------------------'''


def create_fingers_dict():
    """
    Create dictionary by TCP params
    usage: dict[SYN][WIN][TTL] return array with OS and theirs %
    :return: dictionary from file with TCP params
    """
    config = ConfigParser()
    config.read('config.ini')
    finger_path = config.get("TCP", "tcp_path")
    with open(finger_path, 'r') as fingers:
        # ignore header
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


def create_fingers_dict_id():
    """
    Create dictionary by ID of TCP group
    usage: dict[id] return array with OS and theirs %
    :return: dictionary from file with TCP params
    """
    config = ConfigParser()
    config.read('config.ini')
    finger_path = config.get("TCP", "tcp_path")
    with open(finger_path, 'r') as fingers:
        # ignore header
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


'''------------------------------------CONNECT FLOW WITH OS BY DNS AND UPDATES SERVERS------------------------------'''


def is_win(record):
    """
    Test for specific domains
    :param record: line to analyse
    :return: True if is specific for Windows, False otherwise
    """
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
    """
    Test for specific domains
    :param record: line to analyse
    :return: True if is specific for Mac OS X or similar OS, False otherwise
    """
    return mac_reg1.search(record) or mac_reg2.search(record) or mac_reg3.search(record) \
           or mac_reg4.search(record) or mac_reg5.search(record) or mac_reg6.search(record) \
           or mac_reg7.search(record) or mac_reg8.search(record) or mac_reg9.search(record) \
           or mac_reg10.search(record) or mac_reg11.search(record) or mac_reg12.search(record) \
           or mac_reg13.search(record) or mac_reg14.search(record) or mac_reg15.search(record) \
           or mac_reg16.search(record)


def is_lin(record):
    """
    Test for specific domains
    :param record: line to analyse
    :return: True if is specific for Linux, False otherwise
    """
    return linux_reg1.search(record) or linux_reg2.search(record) or linux_reg3.search(record) \
           or linux_reg4.search(record) or linux_reg5.search(record) or linux_reg6.search(record)


def is_android(record):
    """
    Test for specific domains
    :param record: line to analyse
    :return: True if is specific for Android, False otherwise
    """
    return android_reg1.search(record) or android_reg2.search(record) or android_reg3.search(record) \
           or android_reg4.search(record) or android_reg5.search(record) or android_reg6.search(record) \
           or android_reg7.search(record) or android_reg8.search(record) or android_reg9.search(record) \
           or android_reg10.search(record) or android_reg11.search(record) or android_reg12.search(record) \
           or android_reg13.search(record) or android_reg14.search(record) or android_reg15.search(record)


def is_fedora(record):
    """
    Test for specific domains
    :param record: line to analyse
    :return: True if is specific for Fedora, False otherwise
    """
    return fed_reg1.search(record)


def is_blackberry(record):
    """
    Test for specific domains
    :param record: line to analyse
    :return: True if is specific for Blackberry, False otherwise
    """
    return bb_reg1.search(record) or bb_reg2.search(record)


def check_os(record):
    """
    Try to connect flow with OS by specific domains
    :param record: line of flow
    :return: Name of detected OS
    """
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


def calc_os_from_tcp_group(record, raw):
    """
    Calc most probability OS
    :param record: list of all used tcp stacks
    :param raw: if want all os in list as result
    :return: one or more OS with % of accuracy
    """
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


'''--------------------------------RESULTS--------------------------------------------'''

# win_version : win_name
win_map = {'Windows 10.0': 'Windows 10',
           'Windows 6.3': 'Windows 8.1',
           'Windows 6.2': 'Windows 8',
           'Windows 6.1': 'Windows 7',
           'Windows 6.0': 'Windows Vista',
           'Windows 5.2': 'Windows XP Professional x64',
           'Windows 5.1': 'Windows XP',
           'Windows 5.0': 'Windows 2000'}


def convert_win_version(os):
    """
    Convert windows version to windows name
    :param os: windows version
    :return: windows name
    """
    if os in win_map:
        return win_map[os]
    return os


def final_os(data):
    """
    Compare gained data from UA, TCP and specific domain with each other
    :param data: all data from one session
    :return: most probability OS
    """
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
    if tcp is not None:
        result = calc_os_from_tcp_group(tcp, True)

    # add ua percents:
    if ua is not None:
        ua_size = 0
        for tmp in ua:
            ua_size += ua[tmp]
        for tmp in ua:
            name = convert_win_version(tmp)
            if tmp in result:
                result[name] += float(100 * ua[tmp] / ua_size)
            else:
                result[name] = float(100 * ua[tmp] / ua_size)

    # add DNS percents:
    if dns is not None:
        for OS in dns:
            if '.' not in OS and OS != '':
                set = False
                for OS_result in result:
                    if OS in OS_result:
                        result[OS_result] += float(100) / len(dns)
                        set = True
                if not set:
                    result[OS] = float(100) / len(dns)
    final_os = "Unknown"
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

    if 'Darwin' in final_os or 'iOS' in final_os or 'Mac' in final_os:
        return final_os

    if apple > (max * 5):
        if Mac >= darwin and Mac >= iOS:
            return 'Mac OS X'
        if iOS >= darwin:
            return 'iOS'
        return 'Darwin'
    return final_os


def make_sessions(flows):
    """
    Parse flows and aggregate it to sessions by src ip
    :param flows: flows to analyse
    :return: list of joined IP address with OS as sessions
    """
    sessions = {}
    for flow in flows:
        ip = flow['srcip']
        OS = flow['hos']
        major = flow['hosmaj']
        minor = flow['hosmin']

        syn = flow['tcpsynsize']
        win = flow['tcpwinsize']
        ttl = flow['tcpttl']

        host = flow['hhost']
        dns = flow['dnsqname']
        url = flow['hurl']

        if ip not in sessions:
            sessions[ip] = [{}, {}, {}]
        session = sessions[ip]

        # UA
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
        if syn != 'N/A' and win != 'N/A' and ttl != 'N/A' and syn.isdigit() and win.isdigit() and ttl.isdigit():
            if int(ttl) > 64:
                ttl = 128
            else:
                ttl = 64
            try:
                OS = fingers_dict[int(syn)][int(win)][ttl]
                if OS[0][0] not in session[1]:
                    session[1][OS[0][0]] = 1
                else:
                    session[1][OS[0][0]] += 1
            except KeyError:
                OS = ''

        # DNS
        OS = check_os(host + dns + url)
        if OS != '':
            if OS not in session[2]:
                session[2][OS] = 1
            else:
                session[2][OS] += 1

    result = {}

    for key, val in sessions.items():
        result[key] = final_os(val)

    return result


fingers_dict = create_fingers_dict()
fingers_dict_id = create_fingers_dict_id()

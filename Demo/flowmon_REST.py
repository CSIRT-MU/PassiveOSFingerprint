from datetime import timedelta
from flowmonclient import FmcClient


def download(domain, username, password, to_time, profile, channels, filter):
    """
    :param domain: for access to rest
    :param username: for access to rest
    :param password: for access to rest
    :param to_time: actual time or time which we want analyse
    :param profile: which we want use
    :param channels: list of channels we want use
    :param filter: filter out uninteresting data
    :return: flows result of query
    """
    output = ['ts', 'te', 'pr', 'sa', 'sp', 'da', 'dp', 'pkt', 'byt', 'fl', 'hos', 'hosmaj', 'hosmin', 'hosbld',
              'tcpwinsize', 'tcpsynsize', 'tcpttl', 'hhost', 'dnsqname', 'hurl']
    from_time = to_time - timedelta(minutes=5)

    flowmon = FmcClient(domain=domain, username=username, password=password)

    raw_analyse = flowmon.analysis.flows(
        showonly=10000,
        profile=profile,
        channels=channels,
        output=output,
        from_timestamp=from_time,
        to_timestamp=to_time,
        filter=filter)

    flow_id = raw_analyse['id']
    flow = flowmon.analysis.results(flow_id)

    return flow

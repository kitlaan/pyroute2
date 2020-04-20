from pyroute2.netlink import nla
from pyroute2.netlink.rtnl import TC_H_ROOT
from pyroute2.netlink.rtnl.tcmsg.common import time2tick
from pyroute2.netlink.rtnl.tcmsg.common import tick2time
from pyroute2.netlink.rtnl.tcmsg.common import percent2u32
from pyroute2.netlink.rtnl.tcmsg.common import u32_percent

parent = TC_H_ROOT


def get_parameters(kwarg):
    delay = time2tick(kwarg.get('delay', 0))  # in microsecond
    limit = kwarg.get('limit', 1000)  # fifo limit (packets) see netem.c:230
    loss = percent2u32(kwarg.get('loss', 0))  # int percentage
    gap = kwarg.get('gap', 0)
    duplicate = percent2u32(kwarg.get('duplicate', 0))
    jitter = time2tick(kwarg.get('jitter', 0))  # in microsecond

    opts = {
        'delay': delay,
        'limit': limit,
        'loss': loss,
        'gap': gap,
        'duplicate': duplicate,
        'jitter': jitter,
        'attrs': []
    }

    # correlation (delay, loss, duplicate)
    delay_corr = percent2u32(kwarg.get('delay_corr', 0))
    loss_corr = percent2u32(kwarg.get('loss_corr', 0))
    dup_corr = percent2u32(kwarg.get('dup_corr', 0))
    if kwarg.get('delay_corr') is not None or kwarg.get('loss_corr') is not None or kwarg.get('dup_corr') is not None:
        # delay_corr requires that both jitter and delay are != 0
        if delay_corr and not (delay and jitter):
            raise Exception('delay correlation requires delay'
                            ' and jitter to be set')
        # loss correlation and loss
        if loss_corr and not loss:
            raise Exception('loss correlation requires loss to be set')
        # duplicate correlation and duplicate
        if dup_corr and not duplicate:
            raise Exception('duplicate correlation requires '
                            'duplicate to be set')

        opts['attrs'].append(['TCA_NETEM_CORR', {'delay_corr': delay_corr,
                                                 'loss_corr': loss_corr,
                                                 'dup_corr': dup_corr}])

    # reorder (probability, correlation)
    prob_reorder = percent2u32(kwarg.get('prob_reorder', 0))
    corr_reorder = percent2u32(kwarg.get('corr_reorder', 0))
    if kwarg.get('prob_reorder') is not None:
        # gap defaults to 1 if equal to 0
        if gap == 0:
            opts['gap'] = gap = 1
        opts['attrs'].append(['TCA_NETEM_REORDER',
                             {'prob_reorder': prob_reorder,
                              'corr_reorder': corr_reorder}])
    else:
        if gap != 0:
            raise Exception('gap can only be set when prob_reorder is set')
        elif corr_reorder != 0:
            raise Exception('corr_reorder can only be set when '
                            'prob_reorder is set')

    # corrupt (probability, correlation)
    prob_corrupt = percent2u32(kwarg.get('prob_corrupt', 0))
    corr_corrupt = percent2u32(kwarg.get('corr_corrupt', 0))
    if kwarg.get('prob_corrupt') is not None:
        opts['attrs'].append(['TCA_NETEM_CORRUPT',
                             {'prob_corrupt': prob_corrupt,
                              'corr_corrupt': corr_corrupt}])
    elif corr_corrupt != 0:
        raise Exception('corr_corrupt can only be set when '
                        'prob_corrupt is set')

    # rate
    rate = kwarg.get('rate', 0)
    packet_overhead = kwarg.get('packet_overhead', 0)
    cell_size = kwarg.get('cell_size', 0)
    cell_overhead = kwarg.get('cell_overhead', 0)
    if kwarg.get('rate') is not None:
        if rate >= 2 ** 32:
            opts['attrs'].append(['TCA_NETEM_RATE64',
                                 {'rate': rate}])
            rate32 = 2 ** 31 - 1
        else:
            rate32 = rate
        opts['attrs'].append(['TCA_NETEM_RATE',
                             {'rate': rate32,
                              'packet_overhead': 0,
                              'cell_size': 0,
                              'cell_overhead': 0}])
    # TODO: Exceptions like the above for non-'rate' fields

    # It is simpler to use the new LATENCY64 and JITTER64 fields, as they are
    # in nanosecond units natively, without having to deal with tick units.
    # If these exist in the payload, the kernel will override the old fields.
    opts['attrs'].append(['TCA_NETEM_LATENCY64',
                         {'delay': kwarg.get('delay', 0) * 1000}])
    opts['attrs'].append(['TCA_NETEM_JITTER64',
                         {'delay': kwarg.get('jitter', 0) * 1000}])

    # TODO
    # delay distribution (dist_size, dist_data)
    return opts


class options(nla):
    nla_map = (('TCA_NETEM_UNSPEC', 'none'),
               ('TCA_NETEM_CORR', 'netem_corr'),
               ('TCA_NETEM_DELAY_DIST', 'none'),
               ('TCA_NETEM_REORDER', 'netem_reorder'),
               ('TCA_NETEM_CORRUPT', 'netem_corrupt'),
               ('TCA_NETEM_LOSS', 'none'),
               ('TCA_NETEM_RATE', 'netem_rate'),
               ('TCA_NETEM_ECN', 'none'),
               ('TCA_NETEM_RATE64', 'netem_rate64'),
               ('TCA_NETEM_PAD', 'none'),
               ('TCA_NETEM_LATENCY64', 'netem_latency64'),
               ('TCA_NETEM_JITTER64', 'netem_jitter64'),
               ('TCA_NETEM_SLOT', 'netem_slot'),
               ('TCA_NETEM_SLOT_DIST', 'none'))

    fields = (('delay', 'I'),
              ('limit', 'I'),
              ('loss', 'I'),
              ('gap', 'I'),
              ('duplicate', 'I'),
              ('jitter', 'I'))

    def decode(self):
        nla.decode(self)
        # old latency/jitter are in tick units
        self['delay'] = tick2time(self['delay'])
        self['jitter'] = tick2time(self['jitter'])
        self['loss'] = round(u32_percent(self['loss']), 2)
        self['duplicate'] = round(u32_percent(self['duplicate']), 2)

    class netem_corr(nla):
        '''correlation'''
        fields = (('delay_corr', 'I'),
                  ('loss_corr', 'I'),
                  ('dup_corr', 'I'))

        def decode(self):
            nla.decode(self)
            self['delay_corr'] = round(u32_percent(self['delay_corr']), 2)
            self['loss_corr'] = round(u32_percent(self['loss_corr']), 2)
            self['dup_corr'] = round(u32_percent(self['dup_corr']), 2)

    class netem_latency64(nla):
        '''latency in 64-bit (nsec unit)'''
        fields = (('delay', 'q'), )

        def decode(self):
            nla.decode(self)
            # convert to usec units
            self['delay'] = float(self['delay']) / 1000

    class netem_jitter64(nla):
        '''jitter in 64-bit (nsec unit)'''
        fields = (('jitter', 'q'), )

        def decode(self):
            nla.decode(self)
            # convert to usec units
            self['jitter'] = float(self['jitter']) / 1000

    class netem_reorder(nla):
        '''reorder has probability and correlation'''
        fields = (('prob_reorder', 'I'),
                  ('corr_reorder', 'I'))

        def decode(self):
            nla.decode(self)
            self['prob_reorder'] = round(u32_percent(self['prob_reorder']), 2)
            self['corr_reorder'] = round(u32_percent(self['corr_reorder']), 2)

    class netem_corrupt(nla):
        '''corruption has probability and correlation'''
        fields = (('prob_corrupt', 'I'),
                  ('corr_corrupt', 'I'))

        def decode(self):
            nla.decode(self)
            self['prob_corrupt'] = round(u32_percent(self['prob_corrupt']), 2)
            self['corr_corrupt'] = round(u32_percent(self['corr_corrupt']), 2)

    class netem_rate64(nla):
        '''rate in 64-bit'''
        fields = (('rate', 'Q'), )

    class netem_rate(nla):
        '''rate'''
        fields = (('rate', 'I'),
                  ('packet_overhead', 'I'),
                  ('cell_size', 'I'),
                  ('cell_overhead', 'I'))

    class netem_slot(nla):
        '''slot'''
        fields = (('min_delay', 'q'),
                  ('max_delay', 'q'),
                  ('max_packets', 'i'),
                  ('max_bytes', 'i'),
                  ('dist_delay', 'q'),
                  ('dist_jitter', 'q'))

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
import pickle

"""
A ruleset to detect overzealous removal of search space, in the case
a partial merge is selected.

         0                     1                      2
 +----------------+  +-------------------+   +-----------------+
 |                |  |                   |   |                 |
 |  0 - *         |  |  10 - ETH_DST:2   |   | 10 - IPV4_DST:1 |
 |       GOTO: 1  |  |        GOTO:2     |   |       OUTPUT:1  |
 |                |  |  0  - *           |   | 0  - *          |
 |                |  |        GOTO:2     |   |       OUTPUT:2  |
 +----------------+  +-------------------+   +-----------------+

When targeting a single table:
A partial merge of ETH_DST:2 and table 3, only merging with (*) OUTPUT:2
will result in ETH_DST:2,IPV4_DST:1 traffic incorrectly output out 2.

The correction to this is also merge with (IPV4_DST:1).

"""

flows = [
    # Table 0
    parser.OFPFlowStats(
        table_id=0,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[parser.OFPInstructionGotoTable(1)]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=10,
        match=parser.OFPMatch(eth_dst=2),
        instructions=[parser.OFPInstructionGotoTable(2)]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[parser.OFPInstructionGotoTable(2)]
    ),
    parser.OFPFlowStats(
        table_id=2,
        priority=10,
        match=parser.OFPMatch(ipv4_dst=1),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionOutput(1)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=2,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionOutput(2)
                ]
            )
        ]
    ),
]


with open('test_partial_merge.pickle', 'wb') as f:
    pickle.dump(flows, f)

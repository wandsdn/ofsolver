from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
import pickle
from os import path

"""
A reverse dependency case where partial placements

          0                         1
 +------------------+     +--------------------+
 |                  |     |                    |
 | 10 + TCP:10      |     | 10 + IP:1          |
 |       drop/empty |     |       Ouput:1      |
 |                  |     |                    |
 | 0  + *           |     | 0  + *             |
 |       Goto:1     |     |       drop/empty   |
 |                  |     |                    |
 +------------------+     +--------------------+

"""

flows = [
    # Table 0, drop all traffic
    parser.OFPFlowStats(
        table_id=0,
        priority=10,
        match=parser.OFPMatch(tcp_dst=10),
        instructions=[]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[parser.OFPInstructionGotoTable(1)]
    ),
    # Table 1, forward
    parser.OFPFlowStats(
        table_id=1,
        priority=10,
        match=parser.OFPMatch(ipv4_dst=1),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_APPLY_ACTIONS, [
                    parser.OFPActionOutput(1)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[]
    ),
]

with open(path.splitext(path.basename(__file__))[0] + ".pickle", 'wb') as f:
    pickle.dump(flows, f)

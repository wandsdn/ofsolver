from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
import pickle

"""
Make the rules for a simple L2 L3 pipeline
                                               ETH_DST 1&2
                                             +--------------+
                                             |              |
                                             | 2 Routing    |
                                             |              |
                                             | IP_DST ->    |
  +-------------+       +--------------+ +--->    OUTPUT    |
  |             |       |              | |   |    SET MAC   |
  | 0 TCP ACL   |       | 1 MAC TERM   | |   |              |
  | (TCP_DST)   |       | ETH_DST ->   | |   |              |
  | DROP        |       |   goto : 2   | |   +--------------+
  |             +------->              +-+
  | else        |       | else         |
  |             |       | goto: 3      |
  | goto: 1     |       |              +-+
  +-------------+       +--------------+ |     ETH_DST 10&11&12
                                         |   +---------------+
                                         |   |               |
                                         |   |  3 L2 FWD     |
                                         |   |               |
                                         +--^+  ETH_DST ->   |
                                             |     OUTPUT    |
                                             |               |
                                             |               |
                                             |               |
                                             |               |
                                             +---------------+

"""

flows = [
    # Table 0
    parser.OFPFlowStats(
        table_id=0,
        priority=1000,
        match=parser.OFPMatch(tcp_dst=80),
        instructions=[]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=1000,
        match=parser.OFPMatch(tcp_dst=443),
        instructions=[]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[parser.OFPInstructionGotoTable(1)]
    ),

    # Table 1
    parser.OFPFlowStats(
        table_id=1,
        priority=1000,
        match=parser.OFPMatch(eth_dst=1),
        instructions=[parser.OFPInstructionGotoTable(2)]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=1000,
        match=parser.OFPMatch(eth_dst=2),
        instructions=[parser.OFPInstructionGotoTable(2)]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[parser.OFPInstructionGotoTable(3)]
    ),

    # Table 2
    parser.OFPFlowStats(
        table_id=2,
        priority=1008,
        match=parser.OFPMatch(ipv4_dst=("1.0.0.0", "255.0.0.0")),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionSetField(eth_src=100),
                    parser.OFPActionSetField(eth_dst=20),
                    parser.OFPActionOutput(20)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=2,
        priority=1008,
        match=parser.OFPMatch(ipv4_dst=("10.0.0.0", "255.0.0.0")),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionSetField(eth_src=100),
                    parser.OFPActionSetField(eth_dst=20),
                    parser.OFPActionOutput(20)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=2,
        priority=1000,
        match=parser.OFPMatch(ipv4_dst=("0.0.0.0", "0.0.0.0")),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionSetField(eth_src=101),
                    parser.OFPActionSetField(eth_dst=21),
                    parser.OFPActionOutput(21)
                ]
            )
        ]
    ),

    # Table 3
    parser.OFPFlowStats(
        table_id=3,
        priority=1000,
        match=parser.OFPMatch(eth_dst=10),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionOutput(10)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=3,
        priority=1000,
        match=parser.OFPMatch(eth_dst=11),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionOutput(11)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=3,
        priority=1000,
        match=parser.OFPMatch(eth_dst=12),
        instructions=[
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionOutput(12)
                ]
            )
        ]
    ),
]


with open('sample_rules.pickle', 'wb') as f:
    pickle.dump(flows, f)

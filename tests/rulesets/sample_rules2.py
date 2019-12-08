from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
import pickle

"""
Make the rules for a simple L2 L3 pipeline

 +----------+           +------------+
 | ETH, IP  |   --->    | TCP filter |
 |   etc    |           +------------+
 +----------+

The opposite of sample.

"""

flows = [
    # Table 0
    parser.OFPFlowStats(
        table_id=0,
        priority=1000,
        match=parser.OFPMatch(eth_dst=1, ipv4_dst=("1.0.0.0", "255.0.0.0")),
        instructions=[
            parser.OFPInstructionGotoTable(1),
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
        table_id=0,
        priority=1000,
        match=parser.OFPMatch(eth_dst=2, ipv4_dst=("1.0.0.0", "255.0.0.0")),
        instructions=[
            parser.OFPInstructionGotoTable(1),
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
        table_id=0,
        priority=1000,
        match=parser.OFPMatch(eth_dst=1, ipv4_dst=("10.0.0.0", "255.0.0.0")),
        instructions=[
            parser.OFPInstructionGotoTable(1),
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
        table_id=0,
        priority=1000,
        match=parser.OFPMatch(eth_dst=2, ipv4_dst=("10.0.0.0", "255.0.0.0")),
        instructions=[
            parser.OFPInstructionGotoTable(1),
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
        table_id=0,
        priority=900,
        match=parser.OFPMatch(eth_dst=1),
        instructions=[
            parser.OFPInstructionGotoTable(1),
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionSetField(eth_src=101),
                    parser.OFPActionSetField(eth_dst=21),
                    parser.OFPActionOutput(21)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=900,
        match=parser.OFPMatch(eth_dst=2),
        instructions=[
            parser.OFPInstructionGotoTable(1),
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionSetField(eth_src=101),
                    parser.OFPActionSetField(eth_dst=21),
                    parser.OFPActionOutput(21)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=100,
        match=parser.OFPMatch(eth_dst=10),
        instructions=[
            parser.OFPInstructionGotoTable(1),
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionOutput(10)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=100,
        match=parser.OFPMatch(eth_dst=11),
        instructions=[
            parser.OFPInstructionGotoTable(1),
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionOutput(11)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=100,
        match=parser.OFPMatch(eth_dst=12),
        instructions=[
            parser.OFPInstructionGotoTable(1),
            parser.OFPInstructionActions(
                ofproto_v1_3.OFPIT_WRITE_ACTIONS, [
                    parser.OFPActionOutput(12)
                ]
            )
        ]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[
            parser.OFPInstructionGotoTable(1)
        ]
    ),

    # Table 1, drop all traffic
    parser.OFPFlowStats(
        table_id=1,
        priority=1000,
        match=parser.OFPMatch(tcp_dst=80),
        instructions=[
            parser.OFPInstructionActions(ofproto_v1_3.OFPIT_CLEAR_ACTIONS, [])
        ]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=1000,
        match=parser.OFPMatch(tcp_dst=443),
        instructions=[
            parser.OFPInstructionActions(ofproto_v1_3.OFPIT_CLEAR_ACTIONS, [])
        ]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[]
    ),
]


with open('sample_rules2.pickle', 'wb') as f:
    pickle.dump(flows, f)

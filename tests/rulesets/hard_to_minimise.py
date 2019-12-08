from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as parser
import pickle

"""
Make rules that form a diamond of dependencies




"""

flows = [
    # Table 0
    parser.OFPFlowStats(
        table_id=0,
        priority=10,
        match=parser.OFPMatch(vlan_vid=(0x1000, 0x1FFE)),
        instructions=[
            parser.OFPInstructionGotoTable(1)
        ]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=10,
        match=parser.OFPMatch(vlan_vid=(0x1002, 0x1FFE)),
        instructions=[
            parser.OFPInstructionGotoTable(1)
        ]
    ),
    parser.OFPFlowStats(
        table_id=0,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[]
    ),

    # Table 1
    parser.OFPFlowStats(
        table_id=1,
        priority=10,
        match=parser.OFPMatch(vlan_vid=0x1000, tcp_dst=80),
        instructions=[
            parser.OFPInstructionGotoTable(2)
        ]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=10,
        match=parser.OFPMatch(vlan_vid=0x1002, tcp_dst=81),
        instructions=[
            parser.OFPInstructionGotoTable(2)
        ]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=10,
        match=parser.OFPMatch(vlan_vid=0x1001, ipv4_dst=1),
        instructions=[
            parser.OFPInstructionGotoTable(2)
        ]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=10,
        match=parser.OFPMatch(vlan_vid=0x1003, ipv4_dst=2),
        instructions=[
            parser.OFPInstructionGotoTable(2)
        ]
    ),
    parser.OFPFlowStats(
        table_id=1,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[]
    ),
    # Table 2
    parser.OFPFlowStats(
        table_id=2,
        priority=10,
        match=parser.OFPMatch(ipv4_dst=1, tcp_dst=81),
        instructions=[
            parser.OFPInstructionActions(ofproto_v1_3.OFPIT_WRITE_ACTIONS,
                actions=[parser.OFPActionOutput(1)])
        ]
    ),
    parser.OFPFlowStats(
        table_id=2,
        priority=10,
        match=parser.OFPMatch(ipv4_dst=2, tcp_dst=80),
        instructions=[
            parser.OFPInstructionActions(ofproto_v1_3.OFPIT_WRITE_ACTIONS,
                actions=[parser.OFPActionOutput(2)])
        ]
    ),
    parser.OFPFlowStats(
        table_id=2,
        priority=0,
        match=parser.OFPMatch(),
        instructions=[]
    )
]


with open('hard_to_minimise.pickle', 'wb') as f:
    pickle.dump(flows, f)

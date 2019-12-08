

DROP_FWD, FWD_DROP:

The order of a FWD vs DROP in a pipeline can vary, and make it hard
to fit rules.

DROP FWD pipeline:
Table 0: ACL allowing a packet to be dropped, TCP port filtering
Table 1: Forwarding, match an IP and output

FWD DROP pipeline (like ofdpa):
Table 0: Forwarding decision, match an IP and add output to action set
Table 1: ACL allowing previous actions to be cleared, i.e. packet to be
         dropped. TCP port filtering.

Here the specific matches and actions do not matter. Simply the idea that
you might have to add an action only to remove it to get through a pipeline.



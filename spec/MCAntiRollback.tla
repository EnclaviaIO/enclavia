--------------------------- MODULE MCAntiRollback ---------------------------
(* Concrete instances for TLC. The .cfg files under models/ pick one of the *)
(* definitions below for each structured constant.                          *)
EXTENDS AntiRollback

ImagesOne == {"A"}
ImagesTwo == {"A", "B"}
ImagesThree == {"A", "B", "C"}   \* C: an image the owner never approved

\* Upgrade template A -> B: valid_from at tick 2 (so valid_from - Tol = 1),
\* and the issued_at an honest backend stamps (1).
LinkAB  == [id |-> 1, from |-> "A", to |-> "B", vf |-> 2, iss |-> 1]
LinksNone == {}
LinksOne  == {LinkAB}

LinkIdsOne == {1}
LinkIdsTwo == {1, 2}

\* What a hostile backend may stamp beyond the template's own values.
IssNone == {}
IssTwo  == {0, 2}     \* back-dated (0) or future-dated (2) issued_at
VfNone  == {}
VfZero  == {0}        \* an earlier valid_from than the owner approved
=============================================================================

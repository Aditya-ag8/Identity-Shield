# improved-v1

Empty by design.

This directory holds the round-2 rule set, authored at M6 after analysing which
variants the `baseline-v1` rules missed. It must stay empty until then.

Rules added here must:

1. generalise on **field sets**, not on specific values (no hardcoded bucket
   names, user names, IP ranges or user-agent substrings);
2. record the miss that motivated them, in the rule's `description`;
3. leave the sealed holdout variants unexamined — they are only run once, at M6.

Adding rules here before the baseline is frozen invalidates the before/after
comparison.

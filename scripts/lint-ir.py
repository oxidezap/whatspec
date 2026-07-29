#!/usr/bin/env python3
"""Check invariants of the generated IR that the JSON Schemas cannot express.

The schemas validate SHAPE: that a field has the keys it should, of the right
types. They cannot say whether the document is *usable* — whether a field the IR
calls an enum actually names its legal values, whether a byte pin is the length
it claims, whether a union carries the variants that make it a union. Those are
the questions a consumer writing a generator in any language has to answer, and
they are what this checks.

Two kinds of finding:

* **errors** — an internal contradiction. A `literalValue` on an integer field
  that is not an integer is not a gap in extraction; it is a document that says
  two things at once. These always fail.
* **counted** — a known, legitimately non-empty state, held to a BASELINE. An
  enum WA composes at runtime cannot be resolved, and the IR records that under
  `dropsByReason` rather than pretending; the count may shrink (extraction
  improved) but a rise means a new construct started slipping through unnoticed.

Network-free and deterministic, so it runs in CI beside the schema validation.

Usage: scripts/lint-ir.py [generated-dir]   (default: ./generated)
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Counted states, with the value observed when this guard was introduced. Raising
# one of these is a deliberate act: it means a constraint the extractor used to
# recover is now being lost, and the number has to be updated with a reason.
BASELINE = {
    "content integer with no byte width": 0,
}

# The enums no extraction path could resolve, by IDENTITY rather than by total.
#
# A single number cannot see a SUBSTITUTION: one field gaining values while another loses
# them holds the sum at 155 and reports `ok`, which is precisely the silent constraint loss
# this file exists to catch. Identity is domain + field name + wire name + accessor, so it
# survives reordering — a positional path would churn on every unrelated insertion. The
# counts are multiplicities: the same wire enum is read at several places.
#
# 155 fields collapse to 30 identities. Adding one, dropping one, or changing a count all
# fail; each is a deliberate act that costs one line here.
# Arrays where the extractor FLATTENED a shape discriminated by an attribute, keyed by
# semantic path and the repeated names. `privacyParser` reads `<category name="last"
# value=…>` into ten sibling `value` fields, losing the discriminator linkage and the
# runtime's output names (`lastSeen`, `callAdd`, …); the same ten also appear correctly
# nested under `category`, so the flat copy is a duplicate rather than the only record.
#
# By identity, not by total: an aggregate let one loss disappear while another appeared.
# Fixing the shape is an extractor change and belongs in its own PR.
FLATTENED_KEYS = {
    "incoming/incoming/3/shape/fields/5/children/0/children|type": 1,
    "incoming/incoming/4/shape/fields|id": 1,
    "iq/stanzas/49/response/fields/0/children/0/children|value": 9,
    "iq/stanzas/50/response/fields/0/children/0/children|value": 1,
    "notif/notifications/12/content/fields|id": 1,
    "notif/notifications/17/content/fields|from,t": 3,
    "notif/notifications/23/content/fields|from": 2,
    "notif/notifications/24/content/fields/8/children|expiration,id,parent_group_jid,participant,reason,request_method,sub_group_suggestion,triggered": 11,
    "notif/notifications/24/content/fields|t": 1,
    "notif/notifications/3/content/fields/7/children|new_lid,old_lid": 2,
    "notif/notifications/3/content/fields|t": 1,
}

UNRESOLVED_ENUMS = {
    "incoming|ack|deprecatedEditMixin|edit|attrEnum": 1,
    "iq|AddParticipantsResponseSuccess|participant|addParticipant|addParticipantsParticipantAddedOrNonRegisteredWaUserParticipantErrorLidResponseMixinGroup|AddParticipantsParticipantAddedResponse|addParticipantsParticipantMixins|ParticipantGroupJoinRequest|membershipApprovalRequestError|maybeAttrEnum": 1,
    "iq|CreateCustomPaymentMethodResponseSuccess|custom_payment_method|accountCustomPaymentMethodCustomPaymentMethodMixin|p2mEligible|maybeAttrEnum": 1,
    "iq|CreateCustomPaymentMethodResponseSuccess|custom_payment_method|accountCustomPaymentMethodCustomPaymentMethodMixin|p2pEligible|maybeAttrEnum": 1,
    "iq|CreateResponseSuccess|description|groupDescription|error|maybeAttrEnum": 1,
    "iq|PromoteDemoteAdminResponseSuccessMultiAdmin|participant|adminParticipant|error|maybeAttrEnum": 1,
    "iq|PromoteDemoteResponseSuccessDemote|participant|demoteParticipant|error|maybeAttrEnum": 1,
    "iq|PromoteDemoteResponseSuccessPromote|participant|promoteParticipant|error|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|defaultCreditP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|defaultCreditP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|defaultCredit|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|defaultDebitP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|defaultDebitP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|defaultDebit|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|isAadhaarEnabled|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|isInternationalPayEnabled|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|isMpinSet|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|p2mEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|p2pEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|bank|bank|pinFormatVersion|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|automaticBinding|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesDefaultEligibleP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesDefaultEligibleP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesDefaultEligible|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesEditable|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesVerifiable|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|comboCardCapabilitiesMixin|capabilitiesP2mCreditEligible|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|comboCardCapabilitiesMixin|capabilitiesP2mDebitEligible|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultCreditP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultCreditP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultCredit|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultDebitP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultDebitP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultDebit|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|needsDeviceBinding|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|p2mEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|p2pEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|verified|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesDefaultEligibleP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesDefaultEligibleP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesDefaultEligible|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesEditable|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesVerifiable|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultCreditP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultCreditP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultCredit|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultDebitP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultDebitP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultDebit|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|p2mEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|p2pEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|verified|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesDefaultEligibleP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesDefaultEligibleP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesDefaultEligible|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesEditable|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesVerifiable|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultCreditP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultCreditP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultCredit|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultDebitP2m|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultDebitP2p|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultDebit|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|p2mEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|p2pEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|verified|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|custom_payment_method|customPaymentMethod|p2mEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|custom_payment_method|customPaymentMethod|p2pEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|canAddPayout|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|canPayout|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|canSell|attrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|p2mEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|p2pEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|payout|payout|payoutBankOrPrepaidCardMixinGroup|PayoutBank|p2mEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|payout|payout|payoutBankOrPrepaidCardMixinGroup|PayoutBank|p2pEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|payout|payout|payoutBankOrPrepaidCardMixinGroup|PayoutPrepaidCard|p2mEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|payout|payout|payoutBankOrPrepaidCardMixinGroup|PayoutPrepaidCard|p2pEligible|maybeAttrEnum": 1,
    "iq|RemoveCustomPaymentMethodResponseSuccess|account|accountPaymentMethodsMixin|merchant|merchant|pixOnboardingState|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|defaultCreditP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|defaultCreditP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|defaultCredit|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|defaultDebitP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|defaultDebitP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|defaultDebit|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|isAadhaarEnabled|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|isInternationalPayEnabled|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|isMpinSet|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|p2mEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|p2pEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|bank|bank|pinFormatVersion|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|automaticBinding|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesDefaultEligibleP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesDefaultEligibleP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesDefaultEligible|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesEditable|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|capabilitiesVerifiable|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|comboCardCapabilitiesMixin|capabilitiesP2mCreditEligible|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|comboCardCapabilitiesMixin|capabilitiesP2mDebitEligible|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultCreditP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultCreditP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultCredit|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultDebitP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultDebitP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|defaultDebit|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|needsDeviceBinding|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|p2mEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|p2pEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|BRCard|verified|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesDefaultEligibleP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesDefaultEligibleP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesDefaultEligible|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesEditable|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|capabilitiesVerifiable|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultCreditP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultCreditP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultCredit|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultDebitP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultDebitP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|defaultDebit|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|p2mEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|p2pEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|ESCard|verified|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesDefaultEligibleP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesDefaultEligibleP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesDefaultEligible|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesEditable|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|capabilitiesVerifiable|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultCreditP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultCreditP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultCredit|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultDebitP2m|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultDebitP2p|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|defaultDebit|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|p2mEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|p2pEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|card|card|bROrMXOrESCardMixinGroup|MXCard|verified|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|custom_payment_method|customPaymentMethod|p2mEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|custom_payment_method|customPaymentMethod|p2pEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|canAddPayout|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|canPayout|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|canSell|attrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|p2mEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|p2pEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|payout|payout|payoutBankOrPrepaidCardMixinGroup|PayoutBank|p2mEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|payout|payout|payoutBankOrPrepaidCardMixinGroup|PayoutBank|p2pEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|payout|payout|payoutBankOrPrepaidCardMixinGroup|PayoutPrepaidCard|p2mEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|payout|payout|payoutBankOrPrepaidCardMixinGroup|PayoutPrepaidCard|p2pEligible|maybeAttrEnum": 1,
    "iq|account|accountPaymentMethodsMixin|merchant|merchant|pixOnboardingState|maybeAttrEnum": 1,
    "iq|custom_payment_method|accountCustomPaymentMethodCustomPaymentMethodMixin|p2mEligible|maybeAttrEnum": 1,
    "iq|custom_payment_method|accountCustomPaymentMethodCustomPaymentMethodMixin|p2pEligible|maybeAttrEnum": 1,
    "iq|description|groupDescription|error|maybeAttrEnum": 1,
    "iq|participant|addParticipant|addParticipantsParticipantAddedOrNonRegisteredWaUserParticipantErrorLidResponseMixinGroup|AddParticipantsParticipantAddedResponse|addParticipantsParticipantMixins|ParticipantGroupJoinRequest|membershipApprovalRequestError|maybeAttrEnum": 1,
    "iq|participant|adminParticipant|error|maybeAttrEnum": 1,
    "iq|participant|promoteParticipant|error|maybeAttrEnum": 1,
    "notif|create|reason|": 1,
}


# `contentInt` reads DECIMAL TEXT, so it has no byte width and must not be asked
# for one; `contentUint(N)` reads N big-endian bytes and must always carry it.
WIDTH_BEARING = {"contentUint"}

# `WamChannel`. Anything else is mapped to `Regular` by the reference generator rather
# than preserved, so an unknown value loses the channel silently instead of failing.
WAM_CHANNELS = {"regular", "realtime", "private"}

# What each accessor may decode to. Deliberately a SET per accessor, not one type: an
# `attrInt` legitimately backs `integer`, `timestamp` and `timestamp_millis`, and a
# one-to-one map would have failed CI on 27 correct fields. Only accessors whose vocabulary
# is settled are listed; anything else is left alone rather than guessed at.
ACCESSOR_TYPES = {
    "attrInt": {"integer", "timestamp", "timestamp_millis"},
    "attrString": {"string"},
    "contentUint": {"integer"},
    "contentBytes": {"bytes"},
    "attrEnum": {"enum"},
    "maybeAttrEnum": {"enum"},
}

# `contentUint(N)` reads N big-endian bytes and `contentBytes` a fixed run; nothing else
# has a byte width. A node with NO accessor is request-side (a `constBytes` pin), which
# carries the length legitimately — 20 of them do.
WIDTH_ACCESSORS = {"contentUint", "contentBytes"}

# The protobuf message appstate actions nest under. Their `protoEnum`/`valueEnumFields`
# paths are written relative to it, so it is the one prefix that may be elided.
APPSTATE_ROOT = "SyncActionValue"

# What the extractor emits for an integer pin, and what a consumer must be able to parse.
DECIMAL = re.compile(r"-?[0-9]+")

# Keys only a response field carries. They identify a `ParsedField` independently of
# whether its `type` is one we know — which is what lets an unrecognized type be
# REPORTED instead of skipped. Deliberately excludes `name`/`type` alone: appstate has
# its own vocabulary (`literal`, `boolString`, `jidOrZero`, proto type names) and the
# notification envelope carries `type` as the notification kind, so keying on those
# would flag correct documents.
FIELD_MARKERS = {
    "method", "wireName", "enumRef", "enumKeys", "literalValue", "byteLength",
    "byteMin", "byteMax", "intMin", "intMax", "unionVariants", "referencePath",
}

# The `ParsedFieldType` vocabulary, mirroring `wa_ir::ParsedFieldType`.
FIELD_TYPES = {
    "string", "integer", "timestamp", "timestamp_millis", "enum", "bytes",
    "jid", "user_jid", "lid_user_jid", "device_jid", "lid_device_jid",
    "group_jid", "newsletter_jid", "call_jid", "broadcast_jid", "status_jid",
    "jid_typed", "bool", "union",
}


def collect_unresolved_enums(data, domain, proto_enums, out):
    """Every enum field no extraction path could resolve, keyed by SEMANTIC path.

    The key is the chain of tags and names from the document root down to the field, so it
    survives reordering — a positional path would churn on every unrelated insertion.
    Aggregating by `domain|name|wireName|method` was not enough: one key stood for as many
    as 18 distinct fields, and a substitution WITHIN a key kept its count and passed. Along
    this path all 155 are distinct, so any substitution changes the set.
    """

    def walk_(node, trail):
        if isinstance(node, dict):
            step = []
            if node.get("tag"):
                step.append(str(node["tag"]))
            elif node.get("wireTag"):
                step.append(str(node["wireTag"]))
            if node.get("name"):
                step.append(str(node["name"]))
            here = trail + step
            if (
                node.get("type") == "enum"
                and not node.get("enumRef")
                and not node.get("enumKeys")
                and not (node.get("protoEnum") and node["protoEnum"] in proto_enums)
            ):
                out["|".join([domain, *here, str(node.get("method", ""))])] += 1
            for k, v in node.items():
                if k in ("tag", "wireTag", "name"):
                    continue
                walk_(v, here)
        elif isinstance(node, list):
            for v in node:
                walk_(v, trail)

    walk_(data, [])


def collect_sync_action_fields(path):
    """`fieldName -> MessageType` for the direct fields of `message SyncActionValue`.

    Scanned by brace DEPTH, not by a non-greedy match: the message contains nested ones,
    and a regex stopping at the first `}` reported all 62 fields as missing.
    """
    try:
        text = path.read_text()
    except OSError:
        return {}
    out, depth, inside = {}, 0, False
    for line in text.splitlines():
        stripped = line.split("//")[0].strip()
        if not inside and re.match(r"message\s+SyncActionValue\s*\{", stripped):
            inside, depth = True, 1
            continue
        if not inside:
            continue
        if depth == 1:
            m = re.match(r"(?:optional|required|repeated)\s+([\w.]+)\s+(\w+)\s*=", stripped)
            if m:
                out[m.group(2)] = m.group(1)
        depth += stripped.count("{") - stripped.count("}")
        if depth <= 0:
            break
    return out


def collect_proto_messages(path):
    """`Outer.Inner` for every protobuf MESSAGE, in the same two forms as the enums.

    `valueProtoType` names one of these, and nothing resolved it — a typo or a removed
    message left mutation tooling unable to build the `SyncActionValue` payload the IR
    claims, while the linter certified the document.
    """
    return _collect_proto(path, "message")


def collect_proto_enums(path):
    """`Outer.Inner` for every ENUM in the committed `.proto`, by brace depth.

    Cheap and text-based on purpose: the linter must stay dependency-free, and the file is
    generated by this same repo. A path naming a message that has no such enum, or naming
    nothing at all, is a dangling reference the schema cannot catch.
    """
    return _collect_proto(path, "enum")


def _collect_proto(path, want):
    try:
        text = path.read_text()
    except OSError:
        return set()
    out, stack = set(), []

    def enclosing():
        for name in reversed(stack):
            if name is not None:
                return name
        return None

    for line in text.splitlines():
        line = line.split("//")[0].strip()
        opens, closes = line.count("{"), line.count("}")
        m = re.match(r"(message|enum)\s+(\w+)", line)
        if m and opens:
            name = m.group(2)
            if m.group(1) == want:
                # Every qualification, not just the immediate parent: a doubly nested enum
                # is written `Outer.Inner.E` in the IR, and emitting only `Inner.E` made a
                # real reference read as dangling (`WASARootSecretAction.RootSecretEntry.
                # Status` was the case that surfaced it).
                # The full path, plus the one form the IR actually writes: appstate paths
                # are relative to `SyncActionValue`, the message every action nests under.
                #
                # Registering EVERY suffix instead was permissive — a bare `Status`
                # resolved — and registering only the absolute path was wrong the other
                # way, since the IR never spells `SyncActionValue`. Exactly these two.
                named = [n for n in stack if n is not None]
                full = [*named, name]
                out.add(".".join(full))
                if full[0] == APPSTATE_ROOT and len(full) > 1:
                    out.add(".".join(full[1:]))
            stack.append(name)
            opens -= 1
        # `oneof`, options, anything else braced. Popping on their `}` as if it closed the
        # enclosing MESSAGE was what made a nested enum come out unqualified — and a real
        # `Outer.E` reference then read as dangling.
        stack.extend([None] * opens)
        for _ in range(closes):
            if stack:
                stack.pop()
    return out


def walk(node, visit, path=""):
    """Depth-first over every dict in the document, with a readable path."""
    if isinstance(node, dict):
        visit(node, path)
        for k, v in node.items():
            walk(v, visit, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, visit, f"{path}/{i}")


def check_field(f, path, domain, errors, counts, proto_enums):
    """Invariants of one `ParsedField`-shaped object."""
    t = f.get("type")
    method = f.get("method", "")

    # An enum that names no legal values is the "is this unconstrained, or did we
    # lose the constraint?" ambiguity the IR exists to remove.
    #
    # `protoEnum` names the values too, just by pointing at a protobuf enum instead of
    # inlining them (appstate's `SettingsSync.settingPlatform`). Omitting it counted two
    # fully-resolved constraints as lost — and since the baseline is a ratchet, a new
    # proto-backed enum could then silently cancel out a genuine unresolved-enum fix
    # while the total held still.
    if (
        t == "enum"
        and not f.get("enumRef")
        and not f.get("enumKeys")
        and not (f.get("protoEnum") and f["protoEnum"] in proto_enums)
    ):
        pass  # counted by `collect_unresolved_enums`, which can see the semantic path

    if method in WIDTH_BEARING and "byteLength" not in f:
        counts["content integer with no byte width"] += 1

    lv = f.get("literalValue")
    # The schema types it as a string; anything else would make the hex scan below iterate
    # a non-iterable and abort the whole run — the same "error path assumes a shape it did
    # not verify" that already crashed this file once.
    if lv is not None and not isinstance(lv, str):
        errors.append(f"{path}: literalValue is {type(lv).__name__}, not a string")
        lv = None
    if lv is not None:
        if t == "integer" and not DECIMAL.fullmatch(lv):
            # NOT `int()`: Python accepts `1_000`, surrounding whitespace and non-ASCII
            # digits, none of which the extractor emits and none of which a Rust (or most
            # other) integer parser will take. The grammar is the contract, not what one
            # language happens to tolerate.
            errors.append(f"{path}: literalValue {lv!r} is not a canonical decimal integer")
        if t == "bytes":
            if any(c not in "0123456789abcdef" for c in lv) or len(lv) % 2:
                errors.append(f"{path}: literalValue {lv!r} is not lowercase hex")
            elif "byteLength" in f and not (
                isinstance(f["byteLength"], int) and not isinstance(f["byteLength"], bool)
            ):
                errors.append(f"{path}: byteLength is {f['byteLength']!r}, not an integer")
            elif "byteLength" in f and len(lv) != f["byteLength"] * 2:
                errors.append(
                    f"{path}: literalValue is {len(lv) // 2} bytes, "
                    f"byteLength says {f['byteLength']}"
                )

    # A union whose alternatives are absent is not a union — a consumer has
    # nothing to switch on.
    if t == "union":
        variants = f.get("unionVariants") or []
        if len(variants) < 2:
            errors.append(f"{path}: union carries fewer than two variants")
        else:
            # Two entries are not two ALTERNATIVES if they answer to the same name. The
            # name is the documented discriminator and the Rust codegen emits it as the
            # variant identifier, so a repeat is either ambiguous or uncompilable.
            # Only real names: a missing one is `None`, and two of those would both
            # count as a duplicate AND make the report `sorted()` a `None` against a
            # `str`. Absence is not a repeat.
            # An EMPTY name is not a name. The codegen runs it through `pascal_case`,
            # which yields the reserved `_` and emits `enum E { _ }` — invalid Rust — so
            # treating "" as a valid unique discriminator certifies something that cannot
            # be generated.
            for i, v in enumerate(variants):
                if isinstance(v, dict) and v.get("name") == "":
                    errors.append(f"{path}: union alternative {i} has an empty name")
            # NORMALIZED, as the generator sees them: `collect_union` runs each through
            # `pascal_case`, so `fooBar` and `foo-bar` emit one variant twice. Same rule
            # already applied to appstate collections and scopes.
            names = [
                pascal_case(v["name"])
                for v in variants
                if isinstance(v, dict) and isinstance(v.get("name"), str) and v["name"]
            ]
            repeated = sorted({n for n in names if names.count(n) > 1})
            if repeated:
                errors.append(
                    f"{path}: union alternative names collide once normalized ({repeated})"
                )

    # Each pair is the two bounds of ONE range accessor. Inverted is a contradiction;
    # so is half of one — the schema permits either key alone, but a consumer handed
    # `intMin` with no `intMax` has a weaker constraint than the wire actually enforces
    # and no way to know it lost the other end.
    for (lo, hi), owner in ((("byteMin", "byteMax"), "bytes"), (("intMin", "intMax"), "integer")):
        if (lo in f) != (hi in f):
            present, missing = (lo, hi) if lo in f else (hi, lo)
            errors.append(f"{path}: {present} without {missing} is half a range")
        elif lo in f:
            # Compared only once both are numbers: `>` between a str and an int raises,
            # and an error path that crashes on malformed input is the failure this file
            # has already hit twice.
            if not all(isinstance(f[k], int) and not isinstance(f[k], bool) for k in (lo, hi)):
                errors.append(f"{path}: {lo}/{hi} are {f[lo]!r}/{f[hi]!r}, not integers")
            elif f[lo] > f[hi]:
                errors.append(f"{path}: {lo} {f[lo]} exceeds {hi} {f[hi]}")
        # A byte range belongs to a bytes field and an integer range to an integer one.
        # On any other type the two halves instruct a consumer to do incompatible things
        # — a string with a numeric range — and it either builds a nonsense validator or
        # drops the constraint. Today every one of them sits on its own type.
        if lo in f and t != owner:
            errors.append(f"{path}: {lo}/{hi} on a {t!r} field, not {owner!r}")

    # A fixed length outside the declared range is two claims no payload can satisfy.
    bl = f.get("byteLength")
    if isinstance(bl, int) and not isinstance(bl, bool):
        lo, hi = f.get("byteMin"), f.get("byteMax")
        if isinstance(lo, int) and not isinstance(lo, bool) and bl < lo:
            errors.append(f"{path}: byteLength {bl} is below byteMin {lo}")
        if isinstance(hi, int) and not isinstance(hi, bool) and bl > hi:
            errors.append(f"{path}: byteLength {bl} is above byteMax {hi}")

    # The accessor and the declared type have to agree: `attrInt` with `type: "string"`
    # tells a consumer to read the wire one way and represent it another.
    allowed = ACCESSOR_TYPES.get(method)
    if allowed is not None and t not in allowed:
        errors.append(
            f"{path}: {method!r} decodes {sorted(allowed)}, not {t!r}"
        )

    # A byte width belongs to an accessor that HAS one.
    if "byteLength" in f and method and method not in WIDTH_ACCESSORS:
        errors.append(f"{path}: byteLength on {method!r}, which has no byte width")

    # A `*Source` is provenance FOR an inferred value. Alone it tells a consumer where a
    # constraint allegedly came from and not what to enforce.
    for src_key, value_keys in (
        ("byteLengthSource", ("byteLength",)),
        ("valueSource", ("value", "constBytes")),
    ):
        if src_key not in f:
            continue
        if not isinstance(f[src_key], str) or not f[src_key]:
            errors.append(f"{path}: {src_key} is {f[src_key]!r}, not a non-empty string")
        if not any(k in f for k in value_keys):
            errors.append(
                f"{path}: {src_key} without {' or '.join(value_keys)} — provenance for "
                f"a value that is not there"
            )

    # An echo rule with no path says "this equals something in the request" and
    # then does not say what.
    if "referencePath" in f and not f["referencePath"]:
        errors.append(f"{path}: referencePath is empty")

    # `ParsedField::reference_path` is documented as mutually exclusive with
    # `literal_value`: one pins a constant, the other pins a value copied from the
    # request. Carried together they are two different answers to "what is this
    # field's value", and a consumer cannot honour both. Checking each key on its own
    # let the pair through — no live case today, which is the point of adding it now.
    if lv is not None and f.get("referencePath"):
        errors.append(
            f"{path}: carries both literalValue and referencePath, "
            f"which pin the value to different things"
        )


def check_enum_ref(node, path, errors, seen_refs=None):
    """An `enumRef` anywhere, not only on a `ParsedField`.

    Request-side and stanza attributes carry one too, keyed by `kind` rather than `type`,
    so gating this on the field-type vocabulary let the pending marker — an empty
    `variants`, which tells a consumer the attribute admits NO value — ship on those
    surfaces unchecked.
    """
    ref = node.get("enumRef")
    if not isinstance(ref, dict):
        return
    if not ref.get("variants"):
        errors.append(f"{path}: enumRef {ref.get('name')!r} has no variants")
        return
    # The same member-name rule the top-level catalog follows: JS keeps only the last
    # repeated property, so two members under one name mean the reference no longer
    # describes what the runtime validates against.
    members = [
        v.get("name")
        for v in ref["variants"]
        if isinstance(v, dict) and isinstance(v.get("name"), str)
    ]
    repeated = sorted({m for m in members if members.count(m) > 1})
    if repeated:
        errors.append(f"{path}: enumRef {ref.get('name')!r} defines {repeated} more than once")

    # `(module, name)` denotes ONE exported enum. `stanza_export` dedups references by it
    # with the first table winning, so two fields carrying that identity with different
    # variants get different constraints depending on traversal order.
    if seen_refs is None:
        return
    ident = (ref.get("module"), ref.get("name"))
    if not all(isinstance(x, str) for x in ident):
        return
    table = tuple(
        (v.get("name"), repr(v.get("value")))
        for v in ref["variants"]
        if isinstance(v, dict)
    )
    prev = seen_refs.setdefault(ident, (table, path))
    if prev[0] != table:
        errors.append(
            f"{path}: enumRef {ident} disagrees with the table at {prev[1]}"
        )


def check_const_bytes(node, path, errors):
    """A request-side `constBytes` pin: the same invariant as a response `literalValue`
    on a bytes field, written differently. Both say "these exact bytes"; only one was
    checked."""
    cb = node.get("constBytes")
    if not isinstance(cb, str):
        return
    # It IS the fixed value of byte content. The emitter honours it whatever `kind` says,
    # so a `dynamic` or `const` node carrying one hands two consumers two different
    # answers depending on which field they dispatch on.
    kind = node.get("kind")
    if kind is not None and kind != "bytes":
        errors.append(f"{path}: constBytes on {kind!r} content, which is not bytes")
    if any(c not in "0123456789abcdef" for c in cb) or len(cb) % 2:
        errors.append(f"{path}: constBytes {cb!r} is not lowercase hex")
    elif "byteLength" in node and not (
        isinstance(node["byteLength"], int) and not isinstance(node["byteLength"], bool)
    ):
        errors.append(f"{path}: byteLength is {node['byteLength']!r}, not an integer")
    elif "byteLength" in node and len(cb) != node["byteLength"] * 2:
        errors.append(
            f"{path}: constBytes is {len(cb) // 2} bytes, "
            f"byteLength says {node['byteLength']}"
        )


def check_enum_catalog_refs(data, domain, errors):
    """Enum references that point INTO the document's own top-level `enums` catalog.

    Every other enum in the IR inlines its values, so `check_enum_ref` — which looks at
    an `enumRef` object in place — is enough. WAM instead names a module and expects the
    consumer to find it in `enums`, and nothing verified the link resolved: a dangling
    name, or a definition left with no variants (which the schema permits), still read as
    "internally consistent" while a consumer could not encode the field at all.

    Keyed on the document HAVING a catalog rather than on the domain name, so a second
    domain adopting the same shape is covered without anyone remembering to add it here.
    """
    catalog = data.get("enums")
    if not isinstance(catalog, list):
        return
    # An EMPTY catalog is not "nothing to check" — it is the worst case. If extraction
    # collapsed the list while the enum-typed fields remained, every reference in the
    # document is dangling, and returning early here reported exactly that document as
    # internally consistent. An empty list is an empty lookup; the walk still runs.
    by_module = {}
    seen_defs = {}
    for i, e in enumerate(catalog):
        if not isinstance(e, dict):
            continue
        # Checked directly, not only through a reference: `generated/enums/` is a catalog
        # nothing in the document points at, so validating references alone left every one
        # of its 326 definitions unexamined. A named enum with no values is the same
        # broken promise whether or not this document happens to cite it.
        if not e.get("variants"):
            errors.append(
                f"{domain}/enums/{i}: enum {e.get('name')!r} is defined with no values"
            )
        # `valueKind` is what tells a consumer how to represent these values; the schema
        # permits any `Scalar` per variant, so it cannot check the two agree. A variant
        # that disagrees would have the consumer pick an incompatible representation.
        # `bool` is excluded explicitly — in Python it IS an int.
        # One member name, one value. JS keeps only the last duplicate property, so a
        # definition carrying both gives a consumer two contradictory answers for the same
        # member — and `uniqueItems` cannot see it, because the objects differ in `value`.
        members = [
            v.get("name") or v.get("key")
            for v in e.get("variants") or []
            if isinstance(v, dict) and isinstance(v.get("name") or v.get("key"), str)
        ]
        repeated = sorted({m for m in members if members.count(m) > 1})
        if repeated:
            errors.append(
                f"{domain}/enums/{i}: enum {e.get('name')!r} defines "
                f"{repeated} more than once"
            )

        expected = {"int": int, "string": str}.get(e.get("valueKind"))
        if expected is not None:
            for j, v in enumerate(e.get("variants") or []):
                # A non-dict entry is malformed IR — exactly what this exists to catch —
                # so it must be REPORTED, not crash the run on `.get`. The value guard
                # below was written defensively; the message beside it was not.
                if not isinstance(v, dict):
                    errors.append(
                        f"{domain}/enums/{i}: enum {e.get('name')!r} variant {j} "
                        f"is {type(v).__name__}, not an object"
                    )
                    continue
                val = v.get("value")
                if not isinstance(val, expected) or isinstance(val, bool):
                    errors.append(
                        f"{domain}/enums/{i}: enum {e.get('name')!r} is valueKind "
                        f"{e.get('valueKind')!r} but variant "
                        f"{(v.get('name') or v.get('key'))!r} carries {val!r}"
                    )
        # WAM ONLY. There, integer members become discriminants of a `#[repr(i64)]` enum
        # and a repeat is E0081. `generated/enums/` is emitted as an untyped `(name,
        # value)` slice, where an upstream ALIAS — two names for one value — is legal and
        # preserved; rejecting it would have failed CI on correct data the next time WA
        # shipped one. The `repr` argument belongs to the WAM generator, not to both.
        vals = [] if domain != "wam" else [
            v.get("value")
            for v in e.get("variants") or []
            if isinstance(v, dict)
            and isinstance(v.get("value"), int)
            and not isinstance(v.get("value"), bool)
        ]
        dup_vals = sorted({v for v in vals if vals.count(v) > 1})
        if dup_vals:
            errors.append(
                f"{domain}/enums/{i}: enum {e.get('name')!r} reuses value(s) {dup_vals}"
            )
        # `(module, name)` is the catalog identity — the extractor dedups on it, and a
        # consumer has no other way to select one definition of a repeated pair.
        ident = (e.get("module"), e.get("name"))
        if not all(isinstance(part, str) for part in ident):
            errors.append(f"{domain}/enums/{i}: identity {ident!r} is not two strings")
        elif ident in seen_defs:
            errors.append(
                f"{domain}/enums/{i}: {ident} already defined at index {seen_defs[ident]}"
            )
        else:
            seen_defs[ident] = i
        # Keyed only when it can BE a key: a dict or list `module` is unhashable and
        # `setdefault` raises. The identity check above already reported it.
        if isinstance(e.get("module"), str):
            by_module.setdefault(e["module"], []).append(e)

    def visit(node, path):
        if node.get("kind") != "enum" or "module" not in node:
            return
        module = node["module"]
        # Hashable check on the REFERENCE side too, not just where definitions are
        # indexed: `by_module.get` on a list or dict raises, and this is a reference
        # walker over arbitrary JSON.
        if not isinstance(module, str):
            errors.append(f"{domain}{path}: enum reference module is {module!r}, not a string")
            return
        found = by_module.get(module, [])
        if not found:
            errors.append(f"{domain}{path}: enum reference {module!r} is in no definition")
        elif len(found) > 1:
            errors.append(
                f"{domain}{path}: enum reference {module!r} matches "
                f"{len(found)} definitions, so it does not identify one"
            )
        elif not found[0].get("variants"):
            errors.append(f"{domain}{path}: enum reference {module!r} resolves to no values")

    walk(data, visit)


def check_event_codes(data, domain, errors):
    """A WAM event's `code` is its wire identifier, so two events cannot share one.

    The schema has no way to say "unique across the array". A consumer generating a
    dispatch table by code would silently overwrite one of the pair, and one of the two
    event shapes would then be unreachable — with nothing in the document indicating it.
    """
    events = data.get("events")
    if not isinstance(events, list):
        return
    seen = {}
    seen_events = {}
    for e in events:
        if not isinstance(e, dict) or "code" not in e:
            continue
        code = e["code"]
        ident = (e.get("module"), e.get("name"))
        if all(isinstance(x, str) for x in ident):
            if ident in seen_events:
                errors.append(
                    f"{domain}: event identity {ident} already defined — JS keeps only "
                    f"the last property under that name"
                )
            else:
                seen_events[ident] = True
        if code in seen:
            errors.append(
                f"{domain}: events {seen[code]!r} and {e.get('name')!r} "
                f"share code {code}, which is the wire identifier"
            )
        else:
            seen[code] = e.get("name")
        # `[default, ring1, ring2]` — the positions ARE the meaning, so a short array does
        # not lose the last ring, it shifts every ring that remains. The schema permits any
        # length.
        # The wire format carries the code in 16 bits, and the reference consumer emits it
        # as `u16`. The schema permits the whole `u32` range, and the extractor turns a
        # negative source literal into a large one — either way the IR would be declared
        # usable and then generate metadata that cannot encode.
        if isinstance(code, int) and not 0 <= code <= 0xFFFF:
            errors.append(
                f"{domain}: event {e.get('name')!r} has code {code}, "
                f"which does not fit the 16-bit wire field"
            )
        # An unrecognised channel is not preserved by the reference generator — it maps
        # to `Regular`, so a typo silently uploads on channel 0 instead of failing.
        channel = e.get("channel")
        if channel is not None and channel not in WAM_CHANNELS:
            errors.append(
                f"{domain}: event {e.get('name')!r} has channel {channel!r}, "
                f"not one of {sorted(WAM_CHANNELS)}"
            )
        # The WAM codec defines this global only for the private channel, so an id on a
        # `regular`/`realtime` event is metadata that cannot be applied where the event
        # says it is sent.
        if e.get("privateStatsId") is not None and channel != "private":
            errors.append(
                f"{domain}: event {e.get('name')!r} declares a privateStatsId on the "
                f"{channel!r} channel"
            )
        weights = e.get("weights")
        if not isinstance(weights, list) or len(weights) != 3:
            errors.append(
                f"{domain}: event {e.get('name')!r} carries "
                f"{len(weights) if isinstance(weights, list) else 'no'} sampling "
                f"weight(s), not the three positions [default, ring1, ring2]"
            )
        # A field's `id` is its wire identifier WITHIN the event, so the same rule applies
        # one level down: an encoder handed two fields sharing an id cannot tell them
        # apart. Scoped per event — ids repeat across events by design.
        by_id = {}
        for f in e.get("fields") or []:
            if not isinstance(f, dict) or "id" not in f:
                continue
            fid = f["id"]
            if isinstance(fid, int) and not 0 <= fid <= 0xFFFF:
                errors.append(
                    f"{domain}: in event {e.get('name')!r}, field {f.get('name')!r} has "
                    f"id {fid}, which does not fit the 16-bit wire field"
                )
            if fid in by_id:
                errors.append(
                    f"{domain}: in event {e.get('name')!r}, fields {by_id[fid]!r} and "
                    f"{f.get('name')!r} share id {fid}"
                )
            else:
                by_id[fid] = f.get("name")
        # JS keeps only the LAST property of a repeated name, so two fields sharing one
        # means the catalog no longer describes the runtime event — and the codegen
        # silently invents a suffixed name rather than failing.
        fnames = [
            f.get("name")
            for f in e.get("fields") or []
            if isinstance(f, dict) and isinstance(f.get("name"), str)
        ]
        repeated = sorted({n for n in fnames if fnames.count(n) > 1})
        if repeated:
            errors.append(
                f"{domain}: event {e.get('name')!r} defines field(s) {repeated} twice"
            )


def check_action_keys(node, path, errors, flattened):
    """`fields`, `constantFields` and `children` are three representations of ONE object
    key namespace, so a name may appear in only one of them.

    Runtime cannot produce two values for one key, and a consumer handed both a wire-read
    `reason` and a constant `reason` has a shape that contradicts itself. Each array is
    internally consistent by construction; nothing compared them to each other.
    """
    arrays = [k for k in ("fields", "constantFields", "children") if isinstance(node.get(k), list)]
    # Two questions, two answers. ACROSS arrays a repeat is a contradiction and fails.
    # WITHIN one array it is the extractor FLATTENING a discriminated shape — ten `value`
    # fields in `privacyParser`, one per `<category name=…>`, with the discriminator and
    # the output names dropped — so it is a known loss held to a baseline, not an error.
    #
    # It was briefly checked as an error, found these 15, and switched off as "alternatives
    # modelled on purpose". Reading the source showed that was wrong. Recording the loss is
    # what this file is for; silently certifying it is what it exists to prevent.
    for key in arrays:
        names_in = [
            it["name"] for it in node[key] if isinstance(it, dict) and "name" in it
        ]
        extra = len(names_in) - len(set(names_in))
        if extra:
            # By IDENTITY, not by total: one loss disappearing while another appears
            # elsewhere kept the aggregate at 42 and passed — the third time this exact
            # blind spot has been found in this file, twice in baselines I wrote.
            repeated = sorted({n for n in names_in if names_in.count(n) > 1})
            flattened[f"{path}/{key}|{','.join(repeated)}"] += extra

    if len(arrays) < 2:
        return
    names = [
        it["name"]
        for k in arrays
        for it in node[k]
        if isinstance(it, dict) and "name" in it
    ]
    repeated = sorted({n for n in names if names.count(n) > 1})
    if repeated:
        errors.append(f"{path}: one key filled twice across fields/constantFields/children: {repeated}")


def check_abprops(data, domain, errors):
    """An A/B config's `default`/`altDefault` are typed by its `valueType`.

    `Scalar` permits every arm and nothing compared the two, so `valueType: "bool"` with a
    string default validated clean and the reference generator would emit contradictory
    `AbPropType::Bool` / `AbDefault::Str` metadata.
    """
    configs = data.get("configs")
    if not isinstance(configs, list):
        return
    seen_ids = {}
    seen_codes = {}
    for i, c in enumerate(configs):
        if not isinstance(c, dict):
            continue
        # `(module, name)` IS the flag identity. Two records under one identity leave a
        # consumer no way to pick; the reference generator just suffixes the second and
        # puts both contradictory entries in `ALL`.
        # The `code` is what the `<props>` IQ sends, so two flags sharing one inside a
        # module leave a consumer unable to associate a returned value with either.
        code_key = (c.get("module"), c.get("code"))
        if all(isinstance(part, (str, int)) and not isinstance(part, bool) for part in code_key):
            if code_key in seen_codes:
                errors.append(
                    f"{domain}/configs/{i}: code {c.get('code')!r} in "
                    f"{c.get('module')!r} already used at index {seen_codes[code_key]}"
                )
            else:
                seen_codes[code_key] = i
        ident = (c.get("module"), c.get("name"))
        if not all(isinstance(part, str) for part in ident):
            errors.append(f"{domain}/configs/{i}: identity {ident!r} is not two strings")
        elif ident in seen_ids:
            errors.append(
                f"{domain}/configs/{i}: {ident} already defined at index {seen_ids[ident]}"
            )
        else:
            seen_ids[ident] = i
        vt = c.get("valueType")
        for key in ("default", "altDefault"):
            if key not in c:
                continue
            v = c[key]
            # `bool` first: in Python it IS an int, so an unordered check would let `True`
            # satisfy `valueType: "int"`.
            if vt == "bool":
                ok = isinstance(v, bool)
            elif vt == "int":
                ok = isinstance(v, int) and not isinstance(v, bool)
            elif vt == "float":
                # A bare integer is not a float literal: the generator emits the value as
                # written, so `AbDefault::Float` would carry an int and a consumer reading
                # the declared type gets a mismatch the schema cannot see.
                ok = isinstance(v, float)
            elif vt == "string":
                ok = isinstance(v, str)
            else:
                continue
            if not ok:
                errors.append(
                    f"{domain}/configs/{i}: {c.get('name')!r} is valueType {vt!r} "
                    f"but its {key} is {v!r}"
                )


def pascal_case(name):
    """A faithful port of `wa_codegen::naming::pascal_case`, which is what actually names
    the generated variants.

    Two approximations preceded this and both certified pairs that cannot compile: the
    first split only on `-`/`_`, missing `fooBar` vs `foo-bar`; the second still missed
    `foo.bar`, because the generator replaces EVERY non-alphanumeric, not three chosen
    ones. It also uppercases the first character without lowering the rest, which
    `.capitalize()` does not do.
    """
    s2 = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    s2 = re.sub(r"([A-Z])([A-Z][a-z])", r"\1 \2", s2)
    s2 = re.sub(r"[^a-zA-Z0-9]", " ", s2)
    return "".join(w[:1].upper() + w[1:] for w in s2.split() if w)


def check_notif_identifiers(data, domain, errors):
    """Notification types and stanza tags become generated Rust identifiers.

    `emit_notification_type_enum` and `StanzaTag` run each through `pascal_case`, so two
    wire spellings that normalise alike emit one variant — and one match arm — twice.
    Same rule already applied to appstate collections, scopes and union alternatives.
    """
    for key, label in (("notifications", "type"), ("stanzaTags", "tag")):
        items = data.get(key)
        if not isinstance(items, list):
            continue
        by_variant = {}
        for it in items:
            raw = it.get(label) if label and isinstance(it, dict) else it
            if not isinstance(raw, str):
                continue
            variant = pascal_case(raw)
            prev = by_variant.setdefault(variant, raw)
            if prev != raw:
                errors.append(
                    f"{domain}/{key}: {raw!r} and {prev!r} both become {variant!r}"
                )


def check_tokens(data, domain, errors):
    """`singleByte[tag]` and `doubleByte[dict][index]` are direct lookups by a wire BYTE.

    Index zero of the single-byte table is reserved: a table that lost its leading empty
    string shifts every token by one, so the consumer encodes and decodes different
    strings than the wire carries — silently, and for everything. And a position past 255
    is unaddressable, so publishing it advertises a token that can be neither encoded nor
    decoded.
    """
    table = data.get("singleByte")
    if isinstance(table, list):
        if not table:
            errors.append(f"{domain}/singleByte: the table is empty")
        else:
            if table[0] != "":
                errors.append(
                    f"{domain}/singleByte[0] is {table[0]!r}; index zero is the reserved slot"
                )
            if len(table) > 256:
                errors.append(
                    f"{domain}/singleByte holds {len(table)} tokens; a one-byte tag "
                    f"addresses at most 256"
                )
    dicts = data.get("doubleByte")
    if isinstance(dicts, list):
        # FOUR, not 256: the wire exposes `DICTIONARY_0`..`DICTIONARY_3` and nothing
        # else, so entries 4 and up have no selector tag and are unreachable.
        if len(dicts) > 4:
            errors.append(
                f"{domain}/doubleByte has {len(dicts)} dictionaries; the wire has four "
                f"selector tags"
            )
        for i, sub in enumerate(dicts):
            if isinstance(sub, list) and len(sub) > 256:
                errors.append(
                    f"{domain}/doubleByte/{i} holds {len(sub)} tokens; the index is one byte"
                )


def check_appstate_collections(data, domain, errors, proto_enums, proto_messages, sync_fields):
    """An action's `collection` must be one the document declares.

    The schema is only a string. `generate_appstate_schemas` builds the `Collection` enum
    from the top-level list alone, so a name absent from it emits a variant that does not
    exist — the certified IR generates uncompilable Rust. An omitted field means `regular`,
    which must therefore be declared too.
    """
    declared = data.get("collections")
    actions = data.get("actions")
    if not isinstance(declared, list) or not isinstance(actions, dict):
        return
    names = [c for c in declared if isinstance(c, str)]
    # Exact repeats first: the set below collapses them, so checking after it would never
    # see a pair that `render_collection_enum` happily emits twice.
    exact = sorted({c for c in names if names.count(c) > 1})
    if exact:
        errors.append(f"{domain}/collections: {exact} listed more than once")
    known = set(names)
    # `render_collection_enum` runs each through `pascal_case` without deduplicating, so
    # two wire names that normalise alike emit the same variant twice and will not compile.
    by_variant = {}
    for c in sorted(known):
        variant = pascal_case(c)
        if variant in by_variant:
            errors.append(
                f"{domain}/collections: {c!r} and {by_variant[variant]!r} both become "
                f"{variant!r}"
            )
        else:
            by_variant[variant] = c
    # Action SCOPES become a generated enum the same way collections do, through the same
    # `pascal_case` — so two spellings that normalise alike emit the variant twice.
    by_scope = {}
    for name, a in sorted(actions.items()):
        if not isinstance(a, dict) or not isinstance(a.get("scope"), str):
            continue
        variant = pascal_case(a["scope"])
        prev = by_scope.setdefault(variant, a["scope"])
        if prev != a["scope"]:
            errors.append(
                f"{domain}/actions/{name}: scopes {a['scope']!r} and {prev!r} both "
                f"become {variant!r}"
            )

    for name, a in sorted(actions.items()):
        if not isinstance(a, dict):
            continue
        used = a.get("collection", "regular")
        # Type-checked before the membership test. `known` holds strings; an unhashable
        # value (a list, a dict) makes `in` raise and takes the whole run down. Fourth time
        # this class has come up here, and it is always the error path, never the check.
        if not isinstance(used, str):
            errors.append(f"{domain}/actions/{name}: collection is {used!r}, not a string")
        elif used not in known:
            errors.append(
                f"{domain}/actions/{name}: collection {used!r} is not among "
                f"{sorted(known)}"
            )
        # Position zero of the sync index IS the wire action name. Anything else has the
        # encoder identify the action by one name and build its index under another.
        parts = a.get("indexParts")
        first = parts[0] if isinstance(parts, list) and parts else None
        # `valueProtoType` names the `SyncActionValue` payload message. A typo or a
        # removed message leaves mutation tooling unable to build what the IR declares,
        # and the generator publishes the string unchanged.
        vpt = a.get("valueProtoType")
        if isinstance(vpt, str) and vpt not in proto_messages:
            errors.append(
                f"{domain}/actions/{name}: valueProtoType {vpt!r} is in no committed "
                f"protobuf message"
            )
        # The FIELD too, and that the two agree: a consumer places the message into the
        # `SyncActionValue` field this names, so a wrong name — or a real name typed as a
        # different message — leaves the payload unbuildable. Checking only that the
        # message exists somewhere left `valueField` entirely unverified.
        vf = a.get("valueField")
        if isinstance(vf, str) and isinstance(vpt, str):
            declared = sync_fields.get(vf)
            if declared is None:
                errors.append(
                    f"{domain}/actions/{name}: valueField {vf!r} is not a field of "
                    f"SyncActionValue"
                )
            elif declared.split(".")[-1] != vpt.split(".")[-1]:
                errors.append(
                    f"{domain}/actions/{name}: valueField {vf!r} is declared "
                    f"{declared!r}, not {vpt!r}"
                )
        # Each `valueEnumFields` value is a protobuf enum PATH, published unchanged for a
        # consumer to interpret. A typo or a removed enum leaves mutation tooling unable
        # to resolve what the IR claims — and the schema is only a string.
        vef = a.get("valueEnumFields")
        if vef is not None and not isinstance(vef, dict):
            errors.append(f"{domain}/actions/{name}: valueEnumFields is {vef!r}, not a map")
            vef = None
        for field, path_ in sorted((vef or {}).items()):
            if isinstance(path_, str) and path_ not in proto_enums:
                errors.append(
                    f"{domain}/actions/{name}: valueEnumFields[{field!r}] names "
                    f"{path_!r}, which is in no committed protobuf enum"
                )
        # `chatJidIndex` is the POSITION holding the chat JID, passed through unchanged to
        # the encoder — so an out-of-range one indexes past `indexParts`, and one pointing
        # at a non-JID part encodes the wrong component. `null` means "no chat JID", which
        # 47 of the 67 actions legitimately are.
        cji = a.get("chatJidIndex")
        if cji is not None:
            parts_list = parts if isinstance(parts, list) else []
            if not isinstance(cji, int) or isinstance(cji, bool) or not 0 <= cji < len(parts_list):
                errors.append(
                    f"{domain}/actions/{name}: chatJidIndex {cji!r} is not a position in "
                    f"its {len(parts_list)} index part(s)"
                )
            elif not (
                isinstance(parts_list[cji], dict) and parts_list[cji].get("type") == "jid"
            ):
                errors.append(
                    f"{domain}/actions/{name}: chatJidIndex {cji} points at a "
                    f"{parts_list[cji].get('type') if isinstance(parts_list[cji], dict) else parts_list[cji]!r} part, not a jid"
                )
        if not isinstance(first, dict) or first.get("type") != "literal":
            errors.append(
                f"{domain}/actions/{name}: indexParts does not begin with a literal"
            )
        elif first.get("value") != a.get("name"):
            errors.append(
                f"{domain}/actions/{name}: index begins with {first.get('value')!r}, "
                f"not the action name {a.get('name')!r}"
            )


def check_child_requiredness(node, path, errors):
    """Every `NotifActionChild` must SAY whether it is always present.

    Rust reads a missing `required` as `true` through a serde default, but the schema
    cannot carry that: the default makes schemars drop the property from its `required`
    list, so an omission validates clean and a non-Rust consumer — who the IR is for —
    cannot tell "required by default" from "unspecified".

    Driven from the `children` ARRAY. Keying on the child's own `fields` missed a child
    that has none, which `serde(skip_serializing_if = "Vec::is_empty")` makes a perfectly
    ordinary serialized shape.
    """
    children = node.get("children")
    if not isinstance(children, list):
        return
    for i, c in enumerate(children):
        if isinstance(c, dict) and "wireTag" in c and "required" not in c:
            errors.append(
                f"{path}/children/{i}: mapped child does not say whether it is required"
            )


def check_variant_groups(node, path, errors):
    """Each `WapVariantGroup` says exactly one of its alternatives applies.

    With none listed, a REQUIRED group promises a choice and supplies nothing to choose:
    an emitter cannot construct the request, and the generator emits a required field
    whose enum has no variants. An optional group with no alternatives is merely empty.

    Driven from the `variantGroups` ARRAY rather than a group's own keys. `optional` is
    skipped when false, so a required group never carries it — and the first version of
    this, gated on that key being present, never ran on the very groups it was for.
    """
    groups = node.get("variantGroups")
    if not isinstance(groups, list):
        return
    for i, g in enumerate(groups):
        if not isinstance(g, dict):
            errors.append(f"{path}/variantGroups/{i}: not an object")
        elif not g.get("optional") and not g.get("variants"):
            errors.append(
                f"{path}/variantGroups/{i}: required variant group offers no alternative"
            )


def check_assertion(a, path, errors):
    if a.get("kind") == "reference":
        if not a.get("referencePath"):
            errors.append(f"{path}: reference assertion with no referencePath")
        # The path says WHERE in the request the value comes from; `name` says which
        # response attribute has to echo it. With only the path a consumer knows the
        # source of a rule it cannot apply to anything.
        if not a.get("name"):
            errors.append(f"{path}: reference assertion with no target attribute name")
        # Its expected value comes FROM THE REQUEST, so it has none of its own. The
        # reference codegen ignores `value`; another consumer could enforce it, and the
        # two would disagree about the same response rule.
        if a.get("value") is not None:
            errors.append(f"{path}: reference assertion also pins a fixed value")
    if a.get("kind") == "attr" and not a.get("name"):
        errors.append(f"{path}: attr assertion with no attribute name")
    # `WapAttrKind::Const` is documented as "fixed literal value (carried in
    # `WapAttrDef::value`)", but `value` is optional in the schema. Without it the IR
    # tells an emitter the value is fixed and then declines to say to what.
    #
    # Only this direction. `value` is NOT exclusive to const: `kind` is shared with the
    # assertion vocabulary, where `attr` and `content` carry one legitimately (1781 nodes
    # today), so rejecting `value` on non-const kinds would flag correct documents.
    if a.get("kind") == "const" and a.get("value") is None:
        errors.append(f"{path}: const attribute with no value")
    # A `content` assertion IS the fixed text a marker union variant matches on. Without
    # the value a consumer cannot tell when the variant applies. Narrow on purpose: an
    # `attr` assertion may legitimately assert only presence.
    if a.get("kind") == "content" and a.get("value") is None:
        errors.append(f"{path}: content assertion with no value to match")
    # A `tag` assertion IS the expected tag; the incoming and server-request scanners read
    # it from `name`. Without it the assertion can neither enforce nor dispatch a shape.
    if a.get("kind") == "tag" and not a.get("name"):
        errors.append(f"{path}: tag assertion with no tag name")


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "generated")
    errors: list[str] = []
    counts = dict.fromkeys(BASELINE, 0)
    unresolved: dict[str, int] = defaultdict(int)
    flattened: dict[str, int] = defaultdict(int)
    seen_refs: dict[tuple, tuple] = {}

    # The protobuf enums an appstate `protoEnum` may name. A path that resolves to
    # nothing is not a constraint — it only looks like one because the string is present,
    # and the schema accepts any string.
    proto_enums = collect_proto_enums(root / "proto" / "WAProto.proto")
    proto_messages = collect_proto_messages(root / "proto" / "WAProto.proto")
    sync_fields = collect_sync_action_fields(root / "proto" / "WAProto.proto")

    docs = sorted(root.glob("*/index.json"))
    if not docs:
        sys.exit(f"no domain documents under {root}")

    for doc in docs:
        try:
            data = json.loads(doc.read_text())
        except (OSError, json.JSONDecodeError) as e:
            # Reported, not raised: an unreadable document is exactly the malformed input
            # this exists to report, and a traceback tells a CI reader far less than a
            # line naming the file.
            errors.append(f"{doc}: cannot be read as JSON ({e})")
            continue
        domain = doc.parent.name

        def visit(node, path, domain=domain):
            # A field is anything with a KNOWN type, or anything carrying a key only a
            # response field has. The first clause reaches the appstate fields, which
            # carry no `method`/`wireName`; the second is what makes an unrecognized type
            # reportable rather than invisible — keying on the vocabulary alone meant a
            # typo in `type` silently excused the field from every other check.
            # A marker only counts when the object HAS a type: an assertion carries
            # `referencePath` too, and flagging those as untyped fields was the first
            # version of this check reporting four contradictions that were not.
            known = node.get("type") in FIELD_TYPES
            marked = "type" in node and any(k in node for k in FIELD_MARKERS)
            if known or marked:
                if not known:
                    errors.append(
                        f"{domain}{path}: field type {node.get('type')!r} is not in the "
                        f"ParsedFieldType vocabulary"
                    )
                check_field(
                    node, f"{domain}{path}", domain, errors, counts, proto_enums
                )
            # No `reference_path` guard: the IR emits `referencePath`, so that condition
            # excluded nothing (13138 of 13138 nodes passed it) and only read as though it
            # did. Every `kind` value these checks name — `reference`, `attr`, `tag`,
            # `content`, `const` — belongs to exactly one of the two vocabularies, so
            # running them on any node carrying a `kind` is correct as well as honest.
            if "kind" in node:
                check_assertion(node, f"{domain}{path}", errors)
            # Independent of the field gate — see each function's note.
            check_enum_ref(node, f"{domain}{path}", errors, seen_refs)
            check_const_bytes(node, f"{domain}{path}", errors)
            check_action_keys(node, f"{domain}{path}", errors, flattened)
            check_variant_groups(node, f"{domain}{path}", errors)
            check_child_requiredness(node, f"{domain}{path}", errors)

        walk(data, visit)
        # Needs the whole document, not one node: the reference and its definition sit in
        # different subtrees.
        check_enum_catalog_refs(data, domain, errors)
        check_event_codes(data, domain, errors)
        check_abprops(data, domain, errors)
        check_appstate_collections(
            data, domain, errors, proto_enums, proto_messages, sync_fields
        )
        check_tokens(data, domain, errors)
        check_notif_identifiers(data, domain, errors)
        collect_unresolved_enums(data, domain, proto_enums, unresolved)

    ok = True
    # Set difference in BOTH directions, plus the multiplicities. A gain that offsets a
    # loss keeps the total at 155 and is exactly what a scalar cannot see.
    # COUNTS, not just membership: the semantic trail omits array indices for reorder
    # stability, so two sibling fields can share an identity — and with a set, one of them
    # losing its `enumRef` left the set unchanged and passed.
    for ident in sorted(set(flattened) | set(FLATTENED_KEYS)):
        now, was = flattened.get(ident, 0), FLATTENED_KEYS.get(ident, 0)
        if now == was:
            continue
        ok = False
        if was == 0:
            print(f"REGRESSION  newly flattened shape: {ident} (x{now})")
        elif now == 0:
            print(f"IMPROVED    shape no longer flattened: {ident} — drop it")
        else:
            print(f"CHANGED     {ident}: {was} -> {now}")

    for ident in sorted(set(unresolved) | set(UNRESOLVED_ENUMS)):
        now, was = unresolved.get(ident, 0), UNRESOLVED_ENUMS.get(ident, 0)
        if now == was:
            continue
        ok = False
        if was == 0:
            print(f"REGRESSION  newly unresolved enum: {ident} (x{now})")
        elif now == 0:
            print(f"IMPROVED    enum now resolved: {ident} — drop it from the baseline")
        else:
            print(f"CHANGED     {ident}: {was} -> {now} — update the baseline")
    if ok:
        print(
            f"ok          unresolved enums: {sum(unresolved.values())} across "
            f"{len(unresolved)} identities, exactly as pinned"
        )

    for name, observed in sorted(counts.items()):
        allowed = BASELINE[name]
        if observed > allowed:
            print(f"REGRESSION  {name}: {observed} (baseline {allowed})")
            ok = False
        elif observed < allowed:
            # A RATCHET, not an upper bound. Accepting a decrease silently banks the
            # difference as slack: 157 -> 150 followed by seven newly unresolved enums is
            # back at 157 and passes, which is exactly the drift this is supposed to catch.
            # An improvement is real work and updating the number with it costs one line.
            print(f"IMPROVED    {name}: {observed} (baseline {allowed}) — lower the baseline")
            ok = False
        else:
            print(f"ok          {name}: {observed} (baseline {allowed})")

    for e in errors:
        print(f"ERROR       {e}")

    if errors:
        print(f"\n{len(errors)} internal contradiction(s) in the IR")
        return 1
    if not ok:
        print(
            "\na counted state left its baseline — raise means a constraint is being lost, "
            "fall means the baseline owes an update"
        )
        return 1
    print(f"\n{len(docs)} document(s) internally consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())

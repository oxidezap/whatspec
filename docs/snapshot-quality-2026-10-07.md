# September snapshot quality investigation

The current remote HEAD checked on 2026-10-07 was
`1f5167c4cebf263edaf001e06a2497f213c55793`. The comparison baseline was
`1a441f0329c941fcdb238490a6c604550d8a9939`. The intervening commit changes only
16 generated files. Both use IR schema 4.3.0 and the same extractor source.
The reference research report supplied through Library was treated as a set of
claims to recheck. No other repository or real session was used.

| Evidence | Old | New |
|---|---|---|
| WA version | 2.3000.1045368834 | 2.3000.1047483476 |
| Bundles | 516 | 579 |
| Set hash | `99a75bd7a4961e15051172c8b99fc460d57e58f7eb47ea9c46824657dd083e00` | `05609307e68b0f6ccfd2a121a573049999e38b752cfe7155ebbe5c661805751b` |
| Archive SHA-256 | `2edd4b3f8dae50b503e0b15920adc774e2680cdb542396d57608bb0374196ee1` | `22243b9c2ff18a66cea8fd66551821fe0f9f09786d107e2be8284637db86c349` |

Both archives came from `oxidezap/whatspec` release `bundle-store`, named
`bundles-<WA version>-<set hash>.tar.xz`. Restore verified each exact bundle
multiset. TLS in the Rust downloader reported `UnknownIssuer`; `curl` downloaded
the same assets using the environment trust store, without disabling TLS checks.
Restore then consumed the local archives. This is independent of the `gh` API
requests that returned `Forbidden`; the connected GitHub search returned no open
PRs at the initial check.

## Reproduced checks

All 12 real JSON documents in each snapshot pass their emitted schemas with
`jsonschema 4.26.0`. The validator previously returned success for an entirely
empty directory, printing 12 `skip` lines. It now fails missing documents,
missing schemas, malformed JSON, invalid schemas, and unresolved external
references. Eight offline regression tests cover those cases and valid input.

Both snapshots reproduce all 27 checked artifacts with the same release binary
and `update --bundles ... --wa-version ... --check`. The old run took 13.970 s
with peak RSS 2,387,992 KiB; the new run took 13.114 s with peak RSS 2,386,528 KiB.
These are single warm runs measured with Python monotonic time and child-process
resource usage, not benchmarks. They prove reproduction, not protocol completeness.

The lint result still fails six exact baselines. No limit was relaxed. Its old
`IMPROVED ... lower the baseline` diagnosis was unsound without source review;
it now reports a changed state and requests investigation.

| Counted gap | Old baseline | New observed | Attribution |
|---|---:|---:|---|
| IQ attributes without argument paths | 55 | 49 | Privacy recovers 3; KMP catalog departure removes 3 |
| IQ children without argument paths | 12 | 10 | Privacy recovers 1; KMP catalog departure removes 1 |
| MEX undetermined variable presence | 108 | 106 | Removed operations subtract 6; ContactManager adds 3; SmartComposer adds 1 |
| MEX operations with no established presence | 13 | 10 | Four removed operations; one new SmartComposer operation |
| WAM uncataloged-event constructions | 41 | 29 | Indeterminate without per-construction attribution |
| WAM unread construction arguments | 104 | 93 | Identifier arguments 100→89; call 1 and member 3 unchanged; cause indeterminate |

The IQ missing-content count stays at 23 through cancellation: KMP departure
subtracts one while SetAbout's changed selected entry point adds one. An unchanged
total therefore also needs identity-level review.

## Source findings

The compact [source sidecar](snapshot-quality-2026-10-07.sources.json) records
recoverable bundle hashes and AST byte spans for the findings below. All source
inspection used those AST ranges; no `eval`, `vm`, or authenticated client ran.

`WAWebSetPrivacyJob` changes helper `f` from four positional parameters to an
object with `dhash`, `name`, `users`, and `value`. Both versions still construct
`privacy/category` and repeated `user` nodes. The new IR recovers the three
category argument paths and the child's `users[]` path. It also corrects the old
`name/action` and `name/wid` paths to `users[]/action` and `users[]/wid`.
This is recovered extraction quality enabled by an upstream refactor, not a
wire feature removal or proof that all branches are modeled. The old source is
bundle `fd26924373be0ce0e773c304511df62909fa76e11d9294c0509542d3f38f842d`,
bytes 1087286..1090426; the new source is
`7c7be0378ce2e7ff49b9f5909cf8a7d283000af82cc43bc071c2df3541ec5d56`,
bytes 183590..186813.

`WAWebKmpSyncdRequestBuilder` contributed three unaddressed attributes, one child,
and one content value. It is present in the old AST index and not recovered in
the new one. This explains the counter arithmetic but does not establish removal
of app-state protocol support. The source-index API does not report parse errors,
and a renamed or relocated implementation needs separate investigation. Keep
this catalog departure indeterminate.

`WAWebSetAboutJob` is not a proven rename from `setAbout` to `sendSetAbout`.
The new source exports both. It moves the IQ construction into a positional
`sendSetAbout` function, called from the persisted job. The selected IR export
changes, losing the old `content` argument-object path while retaining dynamic
status content. Treat the add/remove pair separately; consumers must not assume
that matching wire shapes establish function identity.

Nine MEX operation names depart and three arrive. The departures are
CreateLabyrinthBackup, DebugLabyrinthInboxSnapshot, DebugLabyrinthRange,
EBMessageMetadataQuery, RotateLabyrinthEpoch, TeamLinkCreateInvitation,
TeamLinkListInvitations, TeamLinkRemoveInvitation, and UploadLabyrinthMessages.
The additions are AccountLinkingAPIGetCerts, UpdateNewsletterAdminProfileSetting,
and useWAWebSmartComposerCoachSuggestedReply. Four departures explain six fewer
undetermined keys and four fewer wholly undetermined operations. The new
SmartComposer operation adds one of each.

ContactManagerCustomerProfiles adds three undetermined presence nodes under
`filters`, accounting for the remainder of the MEX counter change. Its source
now constructs a filters array with `.map`. The operation's persisted ID change
is independently proved by the literal exports in its facebookRelayOperation
module: `27747880408206174` becomes `27796221486653417`. Other changes, including
candidate_lids' shape becoming a string and presence becoming conditional,
remain unclassified pending a focused MEX inference review. An aggregate drop
must not hide those new gaps.

WAM changes from 883 to 874 constructions, 807 to 810 call sites, and 121 to 126
partial sites. These aggregates do not identify the 12 uncataloged-event and
11 unread-argument departures. Neither the lower gap counts nor the higher
call-site count justifies lowering the baselines before per-site attribution.

## Review artifact and remaining work

The generic report contains 472 deltas for this pair, including one opaque
protobuf artifact delta. The checked-in [review ledger](snapshot-quality-2026-10-07.reviews.json)
classifies the privacy improvement and the ContactManager persisted-ID change.
The remaining 470 deltas stay indeterminate; unreviewed is not equivalent to bad.
Generate the report with:

```sh
whatspec diff old-generated generated --json \
  --evidence docs/snapshot-quality-2026-10-07.reviews.json > contracts.json
```

The raw report is 2,501,713 bytes. Full optional source indexes are 14,248,640 and
14,223,916 bytes, with 20,209 and 19,713 recovered module names. Only the focused
sidecar and review ledger are committed. The generated IR is unchanged.

Before the snapshot can pass lint, account for the KMP departure and WAM sites,
and review the new MEX gaps. Coordinate extractor or IQ IR corrections with
those owners. Shared workflows are unchanged; the conformity work can integrate
`python3 -m unittest discover -s scripts/tests -v`. CI must be checked on the
published SHA, and a failing baseline must remain visible until resolved.

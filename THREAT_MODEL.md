# django-dirtyfields threat model

## Overview

An in-process Django model mixin snapshots model values and compares them with later in-memory state. It supports selective update_fields saves, optional M2M comparisons, and a queryset path that disables tracking. It owns no HTTP endpoint, user identity or separate storage service (src/dirtyfields/dirtyfields.py:25; src/dirtyfields/dirtyfields.py:57; src/dirtyfields/dirtyfields.py:222).

The library runs with the same authority as the host Django model. A caller can inspect dirty values, ask whether an instance changed, or save the changed fields. It does not expose a listener, issue credentials, install a tenant model or create an independent audit store. Querysets and model initialization determine whether tracking is active, so consumers must handle disabled tracking as an explicit API state. Security relevance arises when a host uses these results for persistence decisions or sends them to a less-trusted recipient.

| Component | Source |
| --- | --- |
| Mixin snapshot and comparison | src/dirtyfields/dirtyfields.py:57; src/dirtyfields/dirtyfields.py:184 |
| Optional queryset and M2M paths | src/dirtyfields/dirtyfields.py:25; src/dirtyfields/dirtyfields.py:112 |
| Selective persistence and baseline reset | src/dirtyfields/dirtyfields.py:222; src/dirtyfields/dirtyfields.py:227 |
| Package boundary | setup.py:8 |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Library embedded in Django | State snapshot | Model initialization/post_save/refresh → reset_state → selected nondeferred field deep copies | instance._original_state and optional _original_m2m_state in process memory | Caller holding model/diff objects | Model field selection and caller memory/log controls | src/dirtyfields/dirtyfields.py:247 |
| Successful Travis coverage job | Coverage upload | TOXENV=py36-django111-coverage; after_success runs coveralls on generated coverage data | Configured Coveralls report recipient (coveralls.io); coverage covers dirtyfields and tests | Travis uploader, Coveralls and authorized report readers | Coverage-job condition; CI upload authorization, payload contents, report visibility and retention require verification | .travis.yml:51; .travis.yml:54-55; tox.ini:54-63; README.rst:10-11 |
| Tagged Travis build | Package publication | deploy.provider=pypi; on.tags=true and all_branches=true; encrypted password reference | PyPI package under configured publisher smn | Travis build/deploy process, PyPI and package consumers | External tag/release authority and CI/PyPI credential controls; encrypted configuration does not establish deployed access policy | .travis.yml:57-64 |
| Library embedded in Django | Selective save | get_dirty_fields(check_relationship=True) → model.save(update_fields=keys) → host ORM routing | Host model table and host Django DB routing via self.save(update_fields=dirty_fields.keys()) | Host DB and model signal receivers | Caller authorization, model save and DB transaction policy | src/dirtyfields/dirtyfields.py:222 |

## Threat Model, Trust Boundaries, and Assumptions

**Protected assets.** Original and current field values held in process memory, possibly confidential when models contain personal data (src/dirtyfields/dirtyfields.py:165). Correct selective persistence of caller-owned model fields and model baseline lifecycle (src/dirtyfields/dirtyfields.py:222; src/dirtyfields/dirtyfields.py:227).

**Actors and starting authority.** Untrusted input can affect model values only through a host integration; the library does not grant outsiders an object reference or mutation authority. A caller controlling normalization/comparison functions already supplies executable application code.

**Trust boundaries and owned controls.**

- Trusted model construction connects post_save and optionally m2m_changed; reset_state refreshes local baselines. The queryset disable flag is not a permission boundary. Once an enabled instance registers the class-wide post_save receiver, an ordinary save of a disabled instance still reaches reset_state and raises DirtyFieldsDisabled through the guarded _as_dict. Under autocommit the database write can persist despite the save raising; an enclosing transaction changes recovery semantics (src/dirtyfields/dirtyfields.py:40; src/dirtyfields/dirtyfields.py:69-83; src/dirtyfields/dirtyfields.py:120-121; src/dirtyfields/dirtyfields.py:227-231; src/dirtyfields/decorators.py:12-18).
- Fields are filtered by FIELDS_TO_CHECK, deferred and expression values are skipped, values are converted and deep-copied. Configured compare/normalise functions execute with caller process authority (src/dirtyfields/dirtyfields.py:58; src/dirtyfields/dirtyfields.py:121).
- For saved instances, get_dirty_fields returns saved values by default or saved/current pairs in verbose mode. For unsaved instances (_state.adding), every included field is dirty: default output contains current values and verbose output contains saved: None/current pairs; field-selection rules still apply (src/dirtyfields/dirtyfields.py:185-193); callers decide whether those values reach logs, APIs or telemetry. save_dirty_fields delegates to self.save(update_fields=...), so model authorization and transactions remain host responsibilities (src/dirtyfields/dirtyfields.py:184; src/dirtyfields/dirtyfields.py:222).

**Security objectives.** Authorize assignment/persistence before invoking selective saves. Protect returned baselines and verbose diffs as sensitive model data. Do not use dirty state as a substitute for concurrency control, database truth or an audit ledger.

**Assumptions and unresolved controls.**

- Snapshots reflect instance lifecycle; concurrent external updates and transaction rollback semantics require caller design, not an inferred lock or transaction guarantee (src/dirtyfields/dirtyfields.py:227).
- Packaging uses setuptools for django-dirtyfields 1.3.1. The Travis deploy configuration publishes tagged builds from any branch to PyPI as user smn using an encrypted password reference. Current Travis activation, credential validity, tag protection and PyPI account controls are unknown; the checked-in publication path itself is established (setup.py:8; .travis.yml:57-64).
- No database endpoint, business transition policy, audit integration or log collector is supplied. M2M checks default off, relationship comparisons are optional, and deferred/expression values may be omitted; review a real consumer before assigning impact to those choices.

## Attack Surface, Mitigations, and Attacker Stories

These are prioritized hypotheses, not validated vulnerabilities. Each requires its stated caller, data and exposure prerequisites; ordinary use of authority already granted is not a new capability.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | A host returns dirty-field data beyond the recipient’s field/history authorization, including all included current values for an unsaved instance. | The integration exposes get_dirty_fields output without history-equivalent authorization. | Disclosure of saved values overwritten in memory, or populated current fields of an unsaved model even without verbose mode. | Caller chooses fields and verbose mode; no independent outbound recipient exists. | Authorize and minimize output fields for both saved and unsaved instances; treat snapshots as historical data and do not assume non-verbose output excludes current values. | src/dirtyfields/dirtyfields.py:185-193; src/dirtyfields/dirtyfields.py:210 |
| 2 | A user changes a security-sensitive field and a host mistakes selective saving for permission to persist that field. | Host accepts the assignment and relies on dirty membership instead of field/object authorization. | Unauthorized business-state change using the host DB authority. | self.save receives explicit update_fields; host models and database controls still apply. | Authorize assignments and allowed transitions before invoking save_dirty_fields. | src/dirtyfields/dirtyfields.py:222 |
| 2 | A host uses a stale, partial or reset baseline as proof of database truth or a concurrency guard. | A real protected invariant depends on concurrent writers, transaction rollback, deferred fields or omitted expressions. | Lost/incorrect state decisions or incomplete security accounting in the host. | Baseline resets on model lifecycle; field/deferred/expression selection is explicit. | Use database transaction/locking or version rules for shared-state invariants; reserve dirty state for its documented instance role. | src/dirtyfields/dirtyfields.py:137; src/dirtyfields/dirtyfields.py:142; src/dirtyfields/dirtyfields.py:227 |
| 2 | An ordinary save of a disabled instance raises after persistence through an already-registered post_save receiver. | An enabled instance previously registered reset_state for the same model class; a disabled instance is later saved; transaction policy permits the write to persist despite the receiver exception. | Reported failure despite a database change, with inconsistent caller state or unsafe retry behavior. | Disabled dirty-field API calls fail explicitly, but reset_state does not skip disabled instances; host transaction policy determines rollback. | Use enabled instances for ordinary saves until the lifecycle is corrected; do not blindly retry after this exception, reconcile database state, and use an enclosing transaction with exception propagation where atomic failure is required. | src/dirtyfields/dirtyfields.py:76-83; src/dirtyfields/dirtyfields.py:120-121; src/dirtyfields/dirtyfields.py:227-231; src/dirtyfields/decorators.py:12-18 |
| 3 | An integration lets an untrusted caller choose comparison/normalization functions or packaged code. | A demonstrated lower-trust configuration-to-code boundary; ordinary model values cannot select functions. | Execution under host Python authority. | Callables are model class configuration, not a public request interface. | Keep function and package selection under trusted developer/release control. | src/dirtyfields/dirtyfields.py:58; src/dirtyfields/dirtyfields.py:198; setup.py:8 |
| 3 | Unauthorized tag/release or CI credential access replaces a published package used by downstream Django applications. | The configured Travis publication remains operational and an attacker crosses the release/credential boundary; current external controls are unknown. | Malicious package code runs with a consumer application’s existing Python authority. | Tagged-build gate and encrypted credential configuration; no conclusion about live tag protection or account controls. | Restrict protected tag creation and CI secret access, bind publication to reviewed artifacts, and revoke/rotate exposed publication credentials. | .travis.yml:57-64; setup.py:8 |

The successful Travis coverage job also invokes an external Coveralls uploader. Review the actual upload payload, CI authorization and Coveralls reader/retention controls before treating CI coverage data as confined to the build environment; current service activation and controls are unknown (.travis.yml:54-55; README.rst:10-11).

## Severity Calibration (Critical, High, Medium, Low)

| Level | Repository-specific example | Counterexample or limiting prerequisite |
| --- | --- | --- |
| Critical | A demonstrated host integration turns lower-trust callable/package selection into broad privileged code execution. | The repository supplies no remote callable-selection API; ordinary trusted Python customization is not a critical vulnerability. |
| High | A real host bypass permits unauthorized sensitive state changes or disclosure of another user’s confidential baseline. | Requires the host authorization boundary and concrete impact, not just detection of a changed field. |
| Medium | A supported caller workflow loses meaningful consistency or confidentiality because it misuses partial instance state. | Concurrency/transaction and data prerequisites must be shown; no general audit or lock guarantee is established. |
| Low | An isolated caller receives an unexpected dirty result or disabled-state error without shared-state or confidentiality impact. | Developer debugging and authorized local inspection of model values are expected behavior. |

This model uses an independent source-backed architecture pass. Repository citations were checked against the supplied inventory and source lines; application code and external services were not executed. Source-established behavior is distinct from unverified deployment exposure. Revisit the model when the described input, storage, authorization or publication boundaries change.

Repository: github.com/mathspace/django-dirtyfields
Version: c325363a29b3bf73cf54dea7f3831d8132db0307
